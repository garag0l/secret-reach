"""Small builders for offline inventories used across tests."""

from secret_reach.iam import find_principal, parse_principal
from secret_reach.reach import Context, evaluate_inventory

A = "111122223333"
B = "444455556666"
ROLE = f"arn:aws:iam::{A}:role/vendor-x"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def gaad(role_arn=ROLE, *statements, boundary=None):
    name = role_arn.rsplit("/", 1)[-1]
    acct = role_arn.split(":")[4]
    role = {
        "RoleName": name,
        "Arn": role_arn,
        "RolePolicyList": [{"PolicyName": "inline", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
    }
    policies = []
    if boundary is not None:
        b_arn = f"arn:aws:iam::{acct}:policy/boundary"
        role["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": b_arn}
        policies.append(
            {"PolicyName": "boundary", "Arn": b_arn, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": boundary}]}
        )
    return {"RoleDetailList": [role], "UserDetailList": [], "GroupDetailList": [], "Policies": policies}


def secret(name, region="us-east-1", account=A, kms_key=None, policy=None, tags=None):
    return {
        "type": "secretsmanager-secret",
        "arn": f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-AbCdEf",
        "name": name,
        "region": region,
        "kms_key": kms_key,
        "resource_policy": policy,
        "tags": tags or {},
        "details": {},
    }


def key_arn(n="1", region="us-east-1", account=A):
    return f"arn:aws:kms:{region}:{account}:key/0000000{n}-0000-0000-0000-000000000000"


def inventory(resources, iam=None, kms_keys=None, account=A):
    return {
        "format": "secret-reach/inventory@1",
        "account": account,
        "partition": "aws",
        "regions": ["us-east-1"],
        "iam": iam or {},
        "kms_keys": kms_keys or {},
        "resources": resources,
        "errors": [],
    }


def run(inv, principal=ROLE, scps=None, extra_gaads=()):
    p = find_principal([inv.get("iam") or {}, *extra_gaads], parse_principal(principal))
    return {r.name: r for r in evaluate_inventory(Context(p, scps), inv)}
