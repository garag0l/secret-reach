"""The offline inventory ("snapshot") format: secret-bearing resources plus the policies needed to judge access.

A snapshot never contains a secret value. It holds names, ARNs, tags, the names (not values) of environment
variables, resource policies, KMS key metadata and key policies, and the account's IAM authorization details.

    {
      "format": "secret-reach/inventory@1",
      "generated_at": "2026-11-25T12:00:00Z",
      "account": "111122223333",
      "partition": "aws",
      "regions": ["us-east-1"],
      "iam": { ...output of iam:GetAccountAuthorizationDetails... },
      "kms_keys": {
        "arn:aws:kms:us-east-1:111122223333:key/...": {"manager": "CUSTOMER", "aliases": ["alias/app"], "policy": {...}}
      },
      "resources": [
        {"type": "secretsmanager-secret", "arn": "...", "name": "...", "region": "us-east-1",
         "kms_key": "<key ARN or null for the AWS managed key>", "resource_policy": {...} | null,
         "tags": {"owner": "payments"}, "details": {}}
      ],
      "errors": ["ssm us-west-2: AccessDeniedException ..."]
    }
"""

from __future__ import annotations

import json
import re
from pathlib import Path

FORMAT = "secret-reach/inventory@1"

SECRET = "secretsmanager-secret"
SSM = "ssm-parameter"
LAMBDA = "lambda-env"
ECS = "ecs-task-definition"
CODEBUILD = "codebuild-env"
S3 = "s3-bucket"
EC2 = "ec2-user-data"
TYPES = (SECRET, SSM, LAMBDA, ECS, CODEBUILD, S3, EC2)

# String (non-SecureString) SSM parameters are reported only when their name looks like a secret.
SECRET_NAME = re.compile(
    r"(secret|passw(or)?d|passwd|pwd|token|api[-_]?key|apikey|private[-_]?key|credential|creds|"
    r"access[-_]?key|client[-_]?secret|conn(ection)?[-_]?str(ing)?|dsn|webhook|signing|jwt|auth|license[-_]?key)",
    re.I,
)
# S3 buckets that commonly hold credentials: Terraform state, backups, dumps, exported secrets.
STATE_BUCKET = re.compile(
    r"(tfstate|tf-state|terraform|state-?bucket|backup|bak|dump|db-?export|snapshot|secrets?|credentials|vault)", re.I
)


class InventoryError(ValueError):
    pass


def load(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    validate(data)
    return data


def save(data: dict, path: str | Path) -> None:
    validate(data)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8", newline="\n")


def validate(data: dict) -> None:
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise InventoryError(f"not a secret-reach inventory (expected format {FORMAT!r})")
    for k in ("account", "resources"):
        if k not in data:
            raise InventoryError(f"inventory is missing {k!r}")
    for i, r in enumerate(data["resources"]):
        for k in ("type", "arn", "name", "region"):
            if k not in r:
                raise InventoryError(f"resources[{i}] is missing {k!r}")
        if r["type"] not in TYPES:
            raise InventoryError(f"resources[{i}] has unknown type {r['type']!r}")
        for forbidden in ("value", "Value", "SecretString", "SecretBinary", "UserData"):
            if forbidden in r or forbidden in (r.get("details") or {}):
                raise InventoryError(f"resources[{i}] carries a {forbidden!r} field; snapshots must not contain secret values")


def ssm_parameter_arn(partition: str, region: str, account: str, name: str) -> str:
    return f"arn:{partition}:ssm:{region}:{account}:parameter/{name.lstrip('/')}"


def ssm_path_arns(partition: str, region: str, account: str, name: str) -> list[str]:
    """ARNs of every parent path of a hierarchical parameter (what GetParametersByPath is authorised on)."""
    parts = name.strip("/").split("/")[:-1]
    return [ssm_parameter_arn(partition, region, account, "/".join(parts[:i])) for i in range(1, len(parts) + 1)]
