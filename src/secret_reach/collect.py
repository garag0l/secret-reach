"""Live, read-only collection of secret-bearing resources into the inventory format (needs boto3).

Never reads a secret value. The APIs used return metadata only, except three whose responses also contain
environment variable values (lambda:ListFunctions, ecs:DescribeTaskDefinition, codebuild:BatchGetProjects).
For those, this module keeps only variable *names*; values are dropped right after the call and are never
stored, written or printed. `tests/test_no_secret_values.py` enforces this statically (AST scan) and at
runtime (secret values seeded into moto must not show up in any output).
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .inventory import CODEBUILD, EC2, ECS, FORMAT, LAMBDA, S3, SECRET, SECRET_NAME, SSM, STATE_BUCKET, ssm_parameter_arn

# Every AWS API call collection may make, in order. `--dry-run` prints this; tests check that the calls actually made
# under moto are a subset of it.
GLOBAL_CALLS = [
    ("sts:GetCallerIdentity", "once"),
    ("iam:GetAccountAuthorizationDetails", "once (paginated)"),
    ("ec2:DescribeRegions", "once, only with --regions all"),
    ("s3:ListBuckets", "once"),
    ("s3:GetBucketLocation", "per bucket whose name matches the state/backup pattern"),
    ("s3:GetBucketPolicy", "per matching bucket"),
    ("s3:GetBucketEncryption", "per matching bucket"),
    ("s3:GetBucketTagging", "per matching bucket"),
]
REGIONAL_CALLS = [
    ("secretsmanager:ListSecrets", "paginated (metadata only)"),
    ("secretsmanager:GetResourcePolicy", "per secret"),
    ("ssm:DescribeParameters", "paginated (metadata only)"),
    ("ssm:ListTagsForResource", "per reported parameter"),
    ("lambda:ListFunctions", "paginated (env var names kept, values discarded)"),
    ("lambda:GetPolicy", "per function with environment variables"),
    ("lambda:ListTags", "per function with environment variables"),
    ("ecs:ListTaskDefinitions", "paginated, ACTIVE only"),
    ("ecs:DescribeTaskDefinition", "latest ACTIVE revision per family (env names kept, values discarded)"),
    ("codebuild:ListProjects", "paginated"),
    ("codebuild:BatchGetProjects", "batches of 100 (env names kept, values discarded)"),
    ("ec2:DescribeInstances", "paginated (user data is NOT requested)"),
    ("kms:ListAliases", "paginated"),
    ("kms:DescribeKey", "per customer-managed key referenced by a resource"),
    ("kms:GetKeyPolicy", "per customer-managed key referenced by a resource"),
]
ALLOWED_CALLS = {c for c, _ in GLOBAL_CALLS + REGIONAL_CALLS}


def dry_run_lines(regions: list[str] | None) -> list[str]:
    where = ", ".join(regions) if regions else "every enabled region (from ec2:DescribeRegions)"
    lines = ["# API calls secret-reach would make (all read-only; no Get*Value, no WithDecryption, no user data):", ""]
    lines += [f"{c:<40} {note}" for c, note in GLOBAL_CALLS if regions is None or "regions all" not in note]
    lines += ["", f"# in {where}:"]
    lines += [f"{c:<40} {note}" for c, note in REGIONAL_CALLS]
    return lines


def _config():
    from botocore.config import Config

    return Config(retries={"mode": "adaptive", "max_attempts": 10}, user_agent_extra="secret-reach")


def _tags(lst, k="Key", v="Value") -> dict:
    return {t.get(k): t.get(v) for t in lst or [] if isinstance(t, dict)}


def _err(e) -> str:
    code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
    return code or type(e).__name__


def _code(e) -> str:
    return (getattr(e, "response", None) or {}).get("Error", {}).get("Code", "")


class Collector:
    def __init__(self, session, regions: list[str] | None = None, workers: int = 8):
        self.session = session
        self.regions = regions
        self.workers = workers
        self._lock = threading.Lock()
        self._clients: dict = {}
        self.errors: list[str] = []
        self.kms_keys: dict[str, dict] = {}
        self._aliases: dict[str, dict[str, str]] = {}

    def client(self, service: str, region: str | None = None):
        key = (service, region)
        with self._lock:  # boto3 sessions are not thread-safe; clients are
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=_config())
            return self._clients[key]

    def _record(self, where: str, e: Exception) -> None:
        with self._lock:
            self.errors.append(f"{where}: {_err(e)}")

    # ------------------------------------------------------------------ top level

    def run(self) -> dict:
        ident = self.client("sts", self._home()).get_caller_identity()
        self.account = ident["Account"]
        self.partition = ident["Arn"].split(":")[1]
        regions = self.regions or self._all_regions()
        iam = self._gaad()
        resources: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for rs in ex.map(self._region, regions):
                resources += rs
        resources += self._s3()
        self._describe_keys(resources)
        return {
            "format": FORMAT,
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "account": self.account,
            "partition": self.partition,
            "regions": regions,
            "iam": iam,
            "kms_keys": self.kms_keys,
            "resources": resources,
            "errors": sorted(self.errors),
        }

    def _home(self) -> str:
        return self.session.region_name or (self.regions[0] if self.regions else "us-east-1")

    def _all_regions(self) -> list[str]:
        resp = self.client("ec2", self._home()).describe_regions()
        return sorted(r["RegionName"] for r in resp.get("Regions", []))

    def _gaad(self) -> dict:
        merged: dict[str, list] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
        try:
            for page in self.client("iam", self._home()).get_paginator("get_account_authorization_details").paginate():
                for k in merged:
                    merged[k] += page.get(k, [])
        except Exception as e:  # noqa: BLE001 - recorded, the rest of the inventory is still useful
            self._record("iam", e)
        return json.loads(json.dumps(merged, default=str))

    def _region(self, region: str) -> list[dict]:
        out: list[dict] = []
        for name, fn in (
            ("kms", self._kms_aliases),
            ("secretsmanager", self._secrets),
            ("ssm", self._ssm),
            ("lambda", self._lambda),
            ("ecs", self._ecs),
            ("codebuild", self._codebuild),
            ("ec2", self._ec2),
        ):
            try:
                out += fn(region) or []
            except Exception as e:  # noqa: BLE001
                self._record(f"{name} {region}", e)
        return out

    # ------------------------------------------------------------------ KMS

    def _kms_aliases(self, region: str) -> list:
        m: dict[str, str] = {}
        for page in self.client("kms", region).get_paginator("list_aliases").paginate():
            for a in page.get("Aliases", []):
                if a.get("TargetKeyId"):
                    m[a["AliasName"]] = a["TargetKeyId"]
        with self._lock:
            self._aliases[region] = m
        return []

    def _key_arn(self, ref: str | None, region: str) -> str | None:
        """Resolve a key reference to a key ARN. None means an AWS managed default key (alias/aws/...)."""
        if not ref:
            return None
        if ref.startswith("alias/aws/") or ":alias/aws/" in ref:
            return None
        if ref.startswith("arn:") and ":key/" in ref:
            return ref
        alias = ref.split(":", 5)[5] if ref.startswith("arn:") and ":alias/" in ref else ref
        if alias.startswith("alias/"):
            target = self._aliases.get(region, {}).get(alias)
            return f"arn:{self.partition}:kms:{region}:{self.account}:key/{target}" if target else ref
        return f"arn:{self.partition}:kms:{region}:{self.account}:key/{ref}"

    def _describe_keys(self, resources: list[dict]) -> None:
        for arn in sorted({r["kms_key"] for r in resources if r.get("kms_key")}):
            if not arn.startswith("arn:") or ":key/" not in arn:
                continue
            region = arn.split(":")[3]
            kms = self.client("kms", region)
            try:
                meta = kms.describe_key(KeyId=arn)["KeyMetadata"]
                info: dict = {"manager": meta.get("KeyManager"), "policy": None}
                if meta.get("KeyManager") == "CUSTOMER":
                    info["policy"] = json.loads(kms.get_key_policy(KeyId=arn, PolicyName="default")["Policy"])
                self.kms_keys[arn] = info
            except Exception as e:  # noqa: BLE001
                self._record(f"kms {arn}", e)

    # ------------------------------------------------------------------ resource types

    def _secrets(self, region: str) -> list[dict]:
        sm = self.client("secretsmanager", region)
        out = []
        for page in sm.get_paginator("list_secrets").paginate():
            for s in page.get("SecretList", []):
                policy = None
                try:
                    p = sm.get_resource_policy(SecretId=s["ARN"]).get("ResourcePolicy")
                    policy = json.loads(p) if p else None
                except Exception as e:  # noqa: BLE001
                    self._record(f"secretsmanager {region} {s['Name']} policy", e)
                out.append(
                    {
                        "type": SECRET,
                        "arn": s["ARN"],
                        "name": s["Name"],
                        "region": region,
                        "kms_key": self._key_arn(s.get("KmsKeyId"), region),
                        "resource_policy": policy,
                        "tags": _tags(s.get("Tags")),
                        "details": {},
                    }
                )
        return out

    def _ssm(self, region: str) -> list[dict]:
        ssm = self.client("ssm", region)
        out = []
        for page in ssm.get_paginator("describe_parameters").paginate():
            for p in page.get("Parameters", []):
                ptype = p.get("Type")
                if ptype != "SecureString" and not SECRET_NAME.search(p["Name"]):
                    continue
                tags = {}
                try:
                    tags = _tags(ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=p["Name"]).get("TagList"))
                except Exception as e:  # noqa: BLE001
                    self._record(f"ssm {region} {p['Name']} tags", e)
                out.append(
                    {
                        "type": SSM,
                        "arn": ssm_parameter_arn(self.partition, region, self.account, p["Name"]),
                        "name": p["Name"],
                        "region": region,
                        "kms_key": self._key_arn(p.get("KeyId"), region) if ptype == "SecureString" else None,
                        "resource_policy": None,
                        "tags": tags,
                        "details": {"parameter_type": ptype},
                    }
                )
        return out

    def _lambda(self, region: str) -> list[dict]:
        lam = self.client("lambda", region)
        out = []
        for page in lam.get_paginator("list_functions").paginate():
            for f in page.get("Functions", []):
                env_names = sorted((f.get("Environment") or {}).get("Variables") or {})  # keys only
                if not env_names:
                    continue
                arn = f["FunctionArn"]
                policy, tags = None, {}
                try:
                    policy = json.loads(lam.get_policy(FunctionName=arn)["Policy"])
                except Exception as e:  # noqa: BLE001
                    if _code(e) != "ResourceNotFoundException":
                        self._record(f"lambda {region} {f['FunctionName']} policy", e)
                try:
                    tags = lam.list_tags(Resource=arn).get("Tags") or {}
                except Exception as e:  # noqa: BLE001
                    self._record(f"lambda {region} {f['FunctionName']} tags", e)
                out.append(
                    {
                        "type": LAMBDA,
                        "arn": arn,
                        "name": f["FunctionName"],
                        "region": region,
                        "kms_key": self._key_arn(f.get("KMSKeyArn"), region),
                        "resource_policy": policy,
                        "tags": dict(tags),
                        "details": {"env_names": env_names},
                    }
                )
        return out

    def _ecs(self, region: str) -> list[dict]:
        ecs = self.client("ecs", region)
        latest: dict[str, tuple[int, str]] = {}
        for page in ecs.get_paginator("list_task_definitions").paginate(status="ACTIVE"):
            for arn in page.get("taskDefinitionArns", []):
                family, _, rev = arn.rsplit("/", 1)[-1].rpartition(":")
                n = int(rev) if rev.isdigit() else 0
                if family not in latest or n > latest[family][0]:
                    latest[family] = (n, arn)
        out = []
        for family in sorted(latest):
            arn = latest[family][1]
            resp = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
            td = resp["taskDefinition"]
            plain, refs, ref_arns, env_files = [], [], [], 0
            for c in td.get("containerDefinitions", []):
                plain += [f"{c.get('name')}/{e['name']}" for e in c.get("environment") or [] if e.get("name")]
                refs += [f"{c.get('name')}/{s['name']}" for s in c.get("secrets") or [] if s.get("name")]
                ref_arns += [s["valueFrom"] for s in c.get("secrets") or [] if s.get("valueFrom")]
                env_files += len(c.get("environmentFiles") or [])
            if not (plain or refs or env_files):
                continue
            details = {"plaintext_env": plain, "secret_refs": refs, "secret_ref_arns": sorted(set(ref_arns))}
            if env_files:
                details["environment_files"] = env_files
                details["plaintext_env"] = plain + [f"({env_files} environment file(s) in S3)"]
            out.append(
                {
                    "type": ECS,
                    "arn": td["taskDefinitionArn"],
                    "name": family,
                    "region": region,
                    "kms_key": None,
                    "resource_policy": None,
                    "tags": _tags(resp.get("tags"), "key", "value"),
                    "details": details,
                }
            )
        return out

    def _codebuild(self, region: str) -> list[dict]:
        cb = self.client("codebuild", region)
        names: list[str] = []
        for page in cb.get_paginator("list_projects").paginate():
            names += page.get("projects", [])
        out = []
        for i in range(0, len(names), 100):
            for p in cb.batch_get_projects(names=names[i : i + 100]).get("projects", []):
                env = (p.get("environment") or {}).get("environmentVariables") or []
                plain = [e["name"] for e in env if e.get("type", "PLAINTEXT") == "PLAINTEXT"]
                refs = [f"{e['name']} ({e.get('type')})" for e in env if e.get("type", "PLAINTEXT") != "PLAINTEXT"]
                if not env:
                    continue
                out.append(
                    {
                        "type": CODEBUILD,
                        "arn": p["arn"],
                        "name": p["name"],
                        "region": region,
                        "kms_key": None,
                        "resource_policy": None,
                        "tags": _tags(p.get("tags"), "key", "value"),
                        "details": {"plaintext_env": plain, "secret_refs": refs},
                    }
                )
        return out

    def _ec2(self, region: str) -> list[dict]:
        ec2 = self.client("ec2", region)
        out = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if (inst.get("State") or {}).get("Name") == "terminated":
                        continue
                    tags = _tags(inst.get("Tags"))
                    iid = inst["InstanceId"]
                    out.append(
                        {
                            "type": EC2,
                            "arn": f"arn:{self.partition}:ec2:{region}:{self.account}:instance/{iid}",
                            "name": f"{iid} ({tags['Name']})" if tags.get("Name") else iid,
                            "region": region,
                            "kms_key": None,
                            "resource_policy": None,
                            "tags": tags,
                            "details": {},
                        }
                    )
        return out

    def _s3(self) -> list[dict]:
        try:
            s3 = self.client("s3", self._home())
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:  # noqa: BLE001
            self._record("s3", e)
            return []
        out = []
        for b in buckets:
            name = b["Name"]
            m = STATE_BUCKET.search(name)
            if not m:
                continue
            try:
                region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
                region = {"EU": "eu-west-1"}.get(region, region)
            except Exception as e:  # noqa: BLE001
                self._record(f"s3 {name} location", e)
                region = self._home()
            policy, key, tags = None, None, {}
            try:
                policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            except Exception as e:  # noqa: BLE001
                if _code(e) != "NoSuchBucketPolicy":
                    self._record(f"s3 {name} policy", e)
            try:
                rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"].get("Rules", [])
                for rule in rules:
                    d = rule.get("ApplyServerSideEncryptionByDefault") or {}
                    if str(d.get("SSEAlgorithm", "")).startswith("aws:kms"):
                        if region not in self._aliases:
                            try:
                                self._kms_aliases(region)
                            except Exception as e:  # noqa: BLE001
                                self._record(f"kms {region}", e)
                        key = self._key_arn(d.get("KMSMasterKeyID"), region)
            except Exception as e:  # noqa: BLE001
                if _code(e) != "ServerSideEncryptionConfigurationNotFoundError":
                    self._record(f"s3 {name} encryption", e)
            try:
                tags = _tags(s3.get_bucket_tagging(Bucket=name).get("TagSet"))
            except Exception as e:  # noqa: BLE001
                if _code(e) != "NoSuchTagSet":
                    self._record(f"s3 {name} tags", e)
            out.append(
                {
                    "type": S3,
                    "arn": f"arn:{self.partition}:s3:::{name}",
                    "name": name,
                    "region": region,
                    "kms_key": key,
                    "resource_policy": policy,
                    "tags": tags,
                    "details": {"matched": m.group(0)},
                }
            )
        return out


def collect(session, regions: list[str] | None = None, workers: int = 8) -> dict:
    return Collector(session, regions, workers).run()
