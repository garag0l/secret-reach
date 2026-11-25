"""Offline evaluator: identity + boundary + resource policy + KMS key policy + SCP interplay."""

import json
from pathlib import Path

import pytest
from helpers import ROLE, A, B, allow, deny, doc, gaad, inventory, key_arn, run, secret

from secret_reach.iam import load_scps, parse_principal
from secret_reach.policy import Who, action_matches, evaluate, resource_matches

DEMO = Path(__file__).parent.parent / "examples" / "demo-inventory.json"
ADMIN = f"arn:aws:iam::{A}:role/db-admin"
CMK_ONLY_ADMIN = doc({"Effect": "Allow", "Principal": {"AWS": ADMIN}, "Action": "kms:*", "Resource": "*"})
CMK_ROOT = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"})


def status(inv, name, **kw):
    return run(inv, **kw)[name].status


# --------------------------------------------------------------------------- golden case from the issue


def test_golden_get_secret_value_star_but_cmk_policy_does_not_allow_decrypt():
    iam = gaad(ROLE, allow("secretsmanager:GetSecretValue"), allow("kms:Decrypt"))
    inv = inventory(
        [secret("aws-managed"), secret("cmk-protected", kms_key=key_arn())],
        iam,
        {key_arn(): {"manager": "CUSTOMER", "policy": CMK_ONLY_ADMIN}},
    )
    res = run(inv)
    assert res["aws-managed"].status == "readable"
    assert res["cmk-protected"].status == "not-readable"
    assert "key policy does not allow kms:Decrypt" in res["cmk-protected"].reasons[0]


def test_cmk_key_policy_explicit_deny_beats_root_delegation():
    kp = doc(
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"},
        {"Effect": "Deny", "NotPrincipal": {"AWS": ADMIN}, "Action": "kms:Decrypt", "Resource": "*"},
    )
    iam = gaad(ROLE, allow("secretsmanager:GetSecretValue"), allow("kms:Decrypt"))
    inv = inventory([secret("s", kms_key=key_arn())], iam, {key_arn(): {"manager": "CUSTOMER", "policy": kp}})
    r = run(inv)["s"]
    assert r.status == "not-readable" and "key policy denies" in r.reasons[0]


def test_cmk_root_delegation_needs_identity_decrypt():
    def inv(st):
        return inventory(
            [secret("s", kms_key=key_arn())], gaad(ROLE, *st), {key_arn(): {"manager": "CUSTOMER", "policy": CMK_ROOT}}
        )

    assert status(inv([allow("secretsmanager:GetSecretValue")]), "s") == "not-readable"
    assert status(inv([allow("secretsmanager:GetSecretValue"), allow("kms:Decrypt", key_arn())]), "s") == "readable"


def test_cmk_direct_key_policy_grant_without_identity_decrypt():
    kp = doc({"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "kms:Decrypt", "Resource": "*"})
    inv = inventory(
        [secret("s", kms_key=key_arn())],
        gaad(ROLE, allow("secretsmanager:GetSecretValue")),
        {key_arn(): {"manager": "CUSTOMER", "policy": kp}},
    )
    assert status(inv, "s") == "readable"


def test_unknown_key_policy_and_unknown_key_are_conditional():
    iam = gaad(ROLE, allow("secretsmanager:GetSecretValue"), allow("kms:Decrypt"))
    inv = inventory(
        [secret("no-policy", kms_key=key_arn("1")), secret("unknown-key", kms_key=key_arn("2"))],
        iam,
        {key_arn("1"): {"manager": "CUSTOMER", "policy": None}},
    )
    res = run(inv)
    assert res["no-policy"].status == res["unknown-key"].status == "conditional"


# --------------------------------------------------------------------------- resource policies, cross account


def test_resource_policy_cross_account_allow():
    vendor = f"arn:aws:iam::{B}:role/vendor-x"
    vendor_gaad = gaad(vendor, allow("secretsmanager:GetSecretValue"), allow("kms:Decrypt"))
    shared = secret(
        "shared",
        kms_key=key_arn(),
        policy=doc({"Effect": "Allow", "Principal": {"AWS": vendor}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"}),
    )
    unshared = secret("unshared", kms_key=key_arn())
    kp = doc(
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"},
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{B}:root"}, "Action": "kms:Decrypt", "Resource": "*"},
    )
    inv = inventory(
        [shared, unshared, secret("aws-key-shared", policy=shared["resource_policy"])],
        {},
        {key_arn(): {"manager": "CUSTOMER", "policy": kp}},
    )
    res = run(inv, principal=vendor, extra_gaads=[vendor_gaad])
    assert res["shared"].status == "readable"
    assert res["unshared"].status == "not-readable"  # identity allows *, but no resource policy trusts account B
    # AWS managed keys can't be used cross-account, whatever the secret's resource policy says
    assert res["aws-key-shared"].status == "not-readable"
    assert "AWS managed" in res["aws-key-shared"].reasons[0]


def test_cross_account_principal_without_gaad_is_assumed_allowed_and_conditional():
    vendor = f"arn:aws:sts::{B}:assumed-role/vendor-x/session-1"
    pol = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{B}:root"},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }
    )
    kp = doc({"Effect": "Allow", "Principal": {"AWS": B}, "Action": "kms:Decrypt", "Resource": "*"})
    inv = inventory(
        [secret("shared", kms_key=key_arn(), policy=pol), secret("private")],
        {},
        {key_arn(): {"manager": "CUSTOMER", "policy": kp}},
    )
    res = run(inv, principal=vendor)
    assert res["shared"].status == "conditional"
    assert any("identity policies unknown" in n for n in res["shared"].reasons)
    assert res["private"].status == "not-readable"


def test_resource_policy_same_account_direct_grant_and_deny():
    grant = doc({"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"})
    block = doc({"Effect": "Deny", "Principal": "*", "Action": "secretsmanager:*", "Resource": "*"})
    inv = inventory([secret("granted", policy=grant), secret("blocked", policy=block)], gaad(ROLE, allow("secretsmanager:List*")))
    res = run(inv)
    assert res["granted"].status == "readable" and "resource policy" in res["granted"].granted_by[0]
    assert res["blocked"].status == "not-readable"


def test_resource_policy_root_principal_does_not_grant_by_itself_same_account():
    pol = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{A}:root"},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
        }
    )
    assert status(inventory([secret("s", policy=pol)], gaad(ROLE)), "s") == "not-readable"


# --------------------------------------------------------------------------- boundary, explicit deny, NotAction/NotResource


def test_permission_boundary_limits_identity_and_role_resource_policy_grant():
    boundary = doc(allow("ssm:*"))
    grant = doc({"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"})
    inv = inventory(
        [secret("by-identity"), secret("by-resource-policy", policy=grant)], gaad(ROLE, allow("*"), boundary=boundary)
    )
    res = run(inv)
    assert res["by-identity"].status == "not-readable"
    assert "permission boundary" in res["by-identity"].reasons[0]
    assert res["by-resource-policy"].status == "not-readable"


def test_explicit_deny_wins():
    iam = gaad(ROLE, allow("*"), deny("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{A}:secret:prod/*"))
    res = run(inventory([secret("prod/db"), secret("dev/db")], iam))
    assert res["prod/db"].status == "not-readable" and "denies" in res["prod/db"].reasons[0]
    assert res["dev/db"].status == "readable"


def test_not_action_and_not_resource():
    iam = gaad(
        ROLE,
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "secretsmanager:GetSecretValue",
            "NotResource": f"arn:aws:secretsmanager:*:{A}:secret:public/*",
        },
    )
    res = run(inventory([secret("public/banner-key"), secret("prod/db")], iam))
    assert res["public/banner-key"].status == "readable"
    assert res["prod/db"].status == "not-readable"


def test_conditional_allow_and_conditional_deny_are_flagged():
    iam = gaad(
        ROLE,
        allow("secretsmanager:GetSecretValue", Condition={"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}),
    )
    assert status(inventory([secret("s")], iam), "s") == "conditional"
    iam = gaad(
        ROLE,
        allow("secretsmanager:GetSecretValue"),
        deny("secretsmanager:*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}}),
    )
    r = run(inventory([secret("s")], iam))["s"]
    assert r.status == "conditional" and any("conditional Deny" in n for n in r.reasons)


# --------------------------------------------------------------------------- SCPs


def test_scp_deny_and_missing_allow():
    iam = gaad(ROLE, allow("*"))
    inv = inventory([secret("s")], iam)
    assert status(inv, "s", scps=load_scps(doc(deny("secretsmanager:GetSecretValue")))) == "not-readable"
    assert status(inv, "s", scps=load_scps([doc(allow("ec2:*"))])) == "not-readable"
    assert (
        status(inv, "s", scps=load_scps({"Policies": [{"Name": "FullAWSAccess", "Content": json.dumps(doc(allow("*")))}]}))
        == "readable"
    )


# --------------------------------------------------------------------------- other resource types


def _res(type_, arn, name, details=None, **kw):
    return {
        "type": type_,
        "arn": arn,
        "name": name,
        "region": "us-east-1",
        "kms_key": None,
        "resource_policy": None,
        "tags": {},
        "details": details or {},
        **kw,
    }


def test_ssm_path_based_access_and_securestring_kms():
    p = _res(
        "ssm-parameter", f"arn:aws:ssm:us-east-1:{A}:parameter/app/prod/db", "/app/prod/db", {"parameter_type": "SecureString"}
    )
    s = _res(
        "ssm-parameter", f"arn:aws:ssm:us-east-1:{A}:parameter/app/prod/token", "/app/prod/token", {"parameter_type": "String"}
    )
    iam = gaad(ROLE, allow("ssm:GetParametersByPath", f"arn:aws:ssm:us-east-1:{A}:parameter/app"))
    res = run(inventory([p, s], iam))
    assert res["/app/prod/db"].status == "readable"
    assert res["/app/prod/db"].granted_by[0].startswith("ssm:GetParametersByPath")
    assert "SecureString" in res["/app/prod/token"].action


def test_lambda_list_functions_exposes_env_and_function_policy():
    fn = _res("lambda-env", f"arn:aws:lambda:us-east-1:{A}:function:billing", "billing", {"env_names": ["DB_PASSWORD"]})
    assert status(inventory([fn], gaad(ROLE, allow("lambda:ListFunctions"))), "billing") == "readable"
    assert (
        status(inventory([fn], gaad(ROLE, allow("lambda:ListFunctions", f"arn:aws:lambda:*:{A}:function:*"))), "billing")
        == "not-readable"
    )


def test_s3_bucket_policy_prefix_and_kms():
    b = _res("s3-bucket", "arn:aws:s3:::corp-tfstate", "corp-tfstate", {"matched": "tfstate"})
    assert status(inventory([b], gaad(ROLE, allow("s3:GetObject", "arn:aws:s3:::corp-tfstate/*"))), "corp-tfstate") == "readable"
    assert (
        status(inventory([b], gaad(ROLE, allow("s3:GetObject", "arn:aws:s3:::corp-tfstate/env/prod/*"))), "corp-tfstate")
        == "conditional"
    )
    enc = dict(b, kms_key=key_arn())
    keys = {key_arn(): {"manager": "CUSTOMER", "policy": CMK_ONLY_ADMIN}}
    assert status(inventory([enc], gaad(ROLE, allow("s3:*"), allow("kms:*")), keys), "corp-tfstate") == "not-readable"


def test_codebuild_ecs_ec2():
    items = [
        _res("codebuild-env", f"arn:aws:codebuild:us-east-1:{A}:project/deploy", "deploy", {"plaintext_env": ["NPM_TOKEN"]}),
        _res("ecs-task-definition", f"arn:aws:ecs:us-east-1:{A}:task-definition/api:3", "api", {"secret_refs": ["c/KEY"]}),
        _res("ec2-user-data", f"arn:aws:ec2:us-east-1:{A}:instance/i-0123456789abcdef0", "i-0123456789abcdef0"),
    ]
    res = run(inventory(items, gaad(ROLE, allow(["codebuild:BatchGetProjects", "ecs:Describe*"]))))
    assert res["deploy"].status == "readable" and "plaintext" in res["deploy"].action
    assert res["api"].status == "readable" and "references" in res["api"].action
    assert res["i-0123456789abcdef0"].status == "not-readable"


# --------------------------------------------------------------------------- demo inventory used in the README


def test_demo_inventory_expected_statuses():
    inv = json.loads(DEMO.read_text(encoding="utf-8"))
    res = run(inv, principal="arn:aws:sts::111122223333:assumed-role/vendor-x-integration/incident-session")
    got = {n: r.status for n, r in res.items()}
    assert got == {
        "prod/payments/stripe-api-key": "readable",
        "prod/db/master": "not-readable",  # golden: GetSecretValue on * but the CMK key policy doesn't allow decrypt
        "prod/root-credentials": "not-readable",  # explicit deny
        "partner/acme-sftp": "conditional",  # kms:Decrypt only via kms:ViaService condition
        "/app/prod/db-password": "readable",
        "/app/prod/slack-webhook-url": "readable",
        "/infra/vpn-psk": "not-readable",
        "billing-webhook": "readable",
        "api-service": "readable",
        "deploy-prod": "not-readable",  # permission boundary
        "acme-terraform-state": "readable",
        "acme-db-backups": "not-readable",  # bucket policy allows, CMK denies
        "i-0123456789abcdef0 (bastion)": "readable",
    }


# --------------------------------------------------------------------------- evaluator primitives


def test_matching_primitives():
    assert action_matches("secretsmanager:Get*", "secretsmanager:GetSecretValue")
    assert action_matches("SecretsManager:getsecretvalue", "secretsmanager:GetSecretValue")
    assert not resource_matches("arn:aws:s3:::Bucket/*", "arn:aws:s3:::bucket/x")
    assert resource_matches("arn:aws:ssm:*:*:parameter/app/?", "arn:aws:ssm:us-east-1:1:parameter/app/x")


def test_principal_matching():
    w = Who(ROLE, A, ("arn:aws:sts::111122223333:assumed-role/vendor-x/s",))
    assert w.match("*") == "direct"
    assert w.match({"AWS": ROLE}) == "direct"
    assert w.match({"AWS": ["arn:aws:sts::111122223333:assumed-role/vendor-x/s"]}) == "direct"
    assert w.match({"AWS": A}) == "account"
    assert w.match({"AWS": f"arn:aws:iam::{A}:root"}) == "account"
    assert w.match({"Service": "lambda.amazonaws.com"}) is None
    v = evaluate([("rp", {"Effect": "Allow", "Principal": {"AWS": B}, "Action": "*"})], "s3:GetObject", "arn:aws:s3:::b/k", w)
    assert not v.allow


@pytest.mark.parametrize(
    "arn,kind,name",
    [
        ("arn:aws:iam::111122223333:role/path/x/vendor", "role", "vendor"),
        ("arn:aws:sts::111122223333:assumed-role/vendor/i-0abc", "role", "vendor"),
        ("arn:aws-us-gov:iam::111122223333:user/alice", "user", "alice"),
    ],
)
def test_parse_principal(arn, kind, name):
    p = parse_principal(arn)
    assert (p.kind, p.name, p.account) == (kind, name, "111122223333")


def test_parse_principal_rejects_other_arns():
    with pytest.raises(ValueError):
        parse_principal("arn:aws:s3:::bucket")


def test_user_with_group_policy():
    iam = {
        "UserDetailList": [
            {
                "UserName": "ci",
                "Arn": f"arn:aws:iam::{A}:user/ci",
                "GroupList": ["deployers"],
                "UserPolicyList": [],
                "AttachedManagedPolicies": [],
            }
        ],
        "GroupDetailList": [
            {
                "GroupName": "deployers",
                "GroupPolicyList": [{"PolicyName": "g", "PolicyDocument": json.dumps(doc(allow("secretsmanager:*")))}],
                "AttachedManagedPolicies": [],
            }
        ],
        "RoleDetailList": [],
        "Policies": [],
    }
    assert status(inventory([secret("s")], iam), "s", principal=f"arn:aws:iam::{A}:user/ci") == "readable"
