"""Live collection against moto: every resource type, the snapshot round trip, and the API calls actually made."""

import io
import json
import zipfile

import boto3
import pytest
from moto import mock_aws

from secret_reach.cli import main
from secret_reach.collect import ALLOWED_CALLS, Collector, collect
from secret_reach.inventory import load, save
from secret_reach.simulate import cross_check

# Seeded "secret" values are fake and carry a marker so the tests can prove none of them leaks into any output.
MARK = "SRFAKEVALUE"
REGION = "us-east-1"


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


def seed(session):
    acct = session.client("sts").get_caller_identity()["Account"]
    iam = session.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName="vendor-x", AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    iam.put_role_policy(
        RoleName="vendor-x",
        PolicyName="read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "ssm:GetParameter", "lambda:GetFunctionConfiguration"],
                        "Resource": "*",
                    },
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
                ],
            }
        ),
    )
    kms = session.client("kms", region_name=REGION)
    key = kms.create_key(Description="app")["KeyMetadata"]
    kms.create_alias(AliasName="alias/app", TargetKeyId=key["KeyId"])
    # key policy that only trusts some other admin role: the vendor can't decrypt
    kms.put_key_policy(
        KeyId=key["KeyId"],
        PolicyName="default",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{acct}:role/admin"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    sm = session.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name="prod/api-key", SecretString=f"{MARK}-secret-1", Tags=[{"Key": "owner", "Value": "payments"}])
    s2 = sm.create_secret(Name="prod/db", SecretString=f"{MARK}-secret-2", KmsKeyId="alias/app")
    sm.put_resource_policy(
        SecretId=s2["ARN"],
        ResourcePolicy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    sm_eu = session.client("secretsmanager", region_name="eu-west-1")
    sm_eu.create_secret(Name="eu/partner", SecretString=f"{MARK}-secret-3")

    ssm = session.client("ssm", region_name=REGION)
    ssm.put_parameter(Name="/app/db-password", Value=f"{MARK}-param-1", Type="SecureString")
    ssm.put_parameter(Name="/app/api-token", Value=f"{MARK}-param-2", Type="String", Tags=[{"Key": "team", "Value": "api"}])
    ssm.put_parameter(Name="/app/feature-flags", Value="on", Type="String")

    lam = session.client("lambda", region_name=REGION)
    lam.create_function(
        FunctionName="billing",
        Runtime="python3.12",
        Role=role["Arn"],
        Handler="index.handler",
        Code={"ZipFile": _zip()},
        Environment={"Variables": {"STRIPE_SECRET": f"{MARK}-lambda-1", "LOG_LEVEL": "info"}},
        Tags={"owner": "payments"},
    )
    lam.create_function(
        FunctionName="no-env", Runtime="python3.12", Role=role["Arn"], Handler="index.handler", Code={"ZipFile": _zip()}
    )

    ecs = session.client("ecs", region_name=REGION)
    for i in range(2):  # two revisions: only the latest is reported
        ecs.register_task_definition(
            family="api",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/docker/library/nginx:latest",
                    "memory": 128,
                    "environment": [{"name": "DATABASE_URL", "value": f"{MARK}-ecs-{i}"}],
                    "secrets": [{"name": "JWT_KEY", "valueFrom": f"arn:aws:secretsmanager:{REGION}:{acct}:secret:jwt"}],
                }
            ],
            tags=[{"key": "owner", "value": "api"}],
        )
    ecs.register_task_definition(family="plain", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}])

    cb = session.client("codebuild", region_name=REGION)
    cb.create_project(
        name="deploy",
        source={"type": "S3", "location": "corp-artifacts/src.zip"},
        artifacts={"type": "S3", "location": "corp-artifacts"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
            "environmentVariables": [
                {"name": "NPM_TOKEN", "value": f"{MARK}-cb-1", "type": "PLAINTEXT"},
                {"name": "DB_PASS", "value": "/app/db-password", "type": "PARAMETER_STORE"},
            ],
        },
        serviceRole=role["Arn"],
    )

    s3 = session.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="corp-tfstate")
    s3.put_bucket_encryption(
        Bucket="corp-tfstate",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key["Arn"]}}]
        },
    )
    s3.put_bucket_tagging(Bucket="corp-tfstate", Tagging={"TagSet": [{"Key": "owner", "Value": "platform"}]})
    s3.put_bucket_policy(
        Bucket="corp-tfstate",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": role["Arn"]},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::corp-tfstate/*",
                    }
                ],
            }
        ),
    )
    s3.put_object(Bucket="corp-tfstate", Key="terraform.tfstate", Body=f"{MARK}-s3-object".encode())
    s3.create_bucket(Bucket="website-assets")

    ec2 = session.client("ec2", region_name=REGION)
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        UserData=f"#!/bin/sh\nexport TOKEN={MARK}-userdata",
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "bastion"}]}],
    )
    return acct, role["Arn"], key["Arn"]


@pytest.fixture
def aws():
    with mock_aws():
        session = boto3.session.Session(region_name=REGION)
        calls: list[str] = []

        def record(model, **_):
            calls.append(f"{model.service_model.signing_name}:{model.name}")

        acct, role, key = seed(session)
        session.events.register("before-call", record)
        yield session, calls, acct, role, key


def test_collects_every_resource_type(aws):
    session, calls, acct, role, key = aws
    inv = collect(session, [REGION, "eu-west-1"])
    by = {(r["type"], r["name"]): r for r in inv["resources"]}
    assert inv["account"] == acct and inv["errors"] == []

    assert by[("secretsmanager-secret", "prod/api-key")]["tags"] == {"owner": "payments"}
    assert by[("secretsmanager-secret", "prod/api-key")]["kms_key"] is None  # AWS managed default key
    db = by[("secretsmanager-secret", "prod/db")]
    assert db["kms_key"] == key  # alias resolved to the key ARN
    assert db["resource_policy"]["Statement"][0]["Action"] == "secretsmanager:GetSecretValue"
    assert ("secretsmanager-secret", "eu/partner") in by
    assert inv["kms_keys"][key]["manager"] == "CUSTOMER" and inv["kms_keys"][key]["policy"]

    assert by[("ssm-parameter", "/app/db-password")]["details"] == {"parameter_type": "SecureString"}
    assert by[("ssm-parameter", "/app/api-token")]["tags"] == {"team": "api"}
    assert ("ssm-parameter", "/app/feature-flags") not in by  # plain String, harmless name

    fn = by[("lambda-env", "billing")]
    assert fn["details"] == {"env_names": ["LOG_LEVEL", "STRIPE_SECRET"]} and fn["tags"] == {"owner": "payments"}
    assert ("lambda-env", "no-env") not in by

    td = by[("ecs-task-definition", "api")]
    assert td["arn"].endswith("task-definition/api:2")
    assert td["details"]["plaintext_env"] == ["app/DATABASE_URL"] and td["details"]["secret_refs"] == ["app/JWT_KEY"]
    assert td["tags"] == {"owner": "api"}
    assert ("ecs-task-definition", "plain") not in by

    cb = by[("codebuild-env", "deploy")]
    assert cb["details"] == {"plaintext_env": ["NPM_TOKEN"], "secret_refs": ["DB_PASS (PARAMETER_STORE)"]}

    b = by[("s3-bucket", "corp-tfstate")]
    assert b["kms_key"] == key and b["tags"] == {"owner": "platform"} and b["resource_policy"]
    assert ("s3-bucket", "website-assets") not in by

    ec2 = [r for r in inv["resources"] if r["type"] == "ec2-user-data"]
    assert len(ec2) == 1 and ec2[0]["name"].endswith("(bastion)")

    # only read-only, documented calls were made
    assert set(calls) <= ALLOWED_CALLS, set(calls) - ALLOWED_CALLS
    assert "secretsmanager:ListSecrets" in calls and "iam:GetAccountAuthorizationDetails" in calls


def test_snapshot_round_trip_and_no_values_anywhere(aws, tmp_path, capsys):
    session, calls, acct, role, key = aws
    snap = tmp_path / "inv.json"
    save(collect(session, [REGION]), snap)
    raw = snap.read_text(encoding="utf-8")
    assert MARK not in raw
    load(snap)

    outputs = [raw]
    for fmt in ("text", "json", "csv"):
        assert main(["--principal", role, "--inventory", str(snap), "-f", fmt, "--all", "--since", "2026-11-01"]) == 0
        out = capsys.readouterr()
        outputs += [out.out, out.err]
    assert all(MARK not in o for o in outputs)

    result = json.loads(outputs[3])
    st = {r["name"]: r["status"] for r in result["results"]}
    assert st["prod/api-key"] == "readable"
    assert st["prod/db"] == "not-readable"  # CMK key policy doesn't trust the vendor role (golden case, live)
    assert st["/app/db-password"] == "readable"
    assert st["billing"] == "readable"
    assert st["corp-tfstate"] == "not-readable"  # bucket policy allows GetObject, CMK does not
    assert st["deploy"] == "not-readable"
    assert result["principal_known"] is True


def test_snapshot_subcommand_and_live_scan(aws, tmp_path, capsys):
    session, calls, acct, role, key = aws
    out = tmp_path / "snap.json"
    assert main(["snapshot", "-o", str(out), "--regions", REGION]) == 0
    assert load(out)["resources"]
    capsys.readouterr()
    assert main(["--principal", role, "--live", "--regions", REGION, "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["source"] == "live" and data["summary"]["readable"] >= 3


def test_all_regions_uses_describe_regions(aws):
    session, calls, *_ = aws
    regions = Collector(session)._all_regions()
    assert REGION in regions and "eu-west-1" in regions
    assert calls == ["ec2:DescribeRegions"]


def test_access_denied_is_recorded_not_fatal(aws, monkeypatch):
    session, *_ = aws
    from botocore.exceptions import ClientError

    def boom(self, region):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListFunctions")

    monkeypatch.setattr(Collector, "_lambda", boom)
    inv = collect(session, [REGION])
    assert inv["errors"] == ["lambda us-east-1: AccessDeniedException"]
    assert any(r["type"] == "secretsmanager-secret" for r in inv["resources"])


class _FakeIAM:
    def __init__(self, decisions):
        self.decisions = decisions

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns):
        return {
            "EvaluationResults": [
                {"EvalActionName": ActionNames[0], "EvalDecision": self.decisions.get(ActionNames[0], "implicitDeny")}
            ]
        }


class _FakeSession:
    def __init__(self, decisions):
        self.iam = _FakeIAM(decisions)

    def client(self, name, region_name=None):
        return self.iam


def test_simulator_cross_check_reports_disagreement():
    from helpers import ROLE, allow, gaad, inventory, run, secret

    res = list(run(inventory([secret("a")], gaad(ROLE, allow("secretsmanager:GetSecretValue")))).values())
    assert cross_check(_FakeSession({"secretsmanager:GetSecretValue": "allowed"}), ROLE, res) == []
    assert res[0].simulator == "allowed"
    mism = cross_check(_FakeSession({}), ROLE, res)
    assert len(mism) == 1 and "implicitDeny" in mism[0]
