"""Load identity policies for one principal from `aws iam get-account-authorization-details` (GAAD) output."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from .policy import as_list

_ASSUMED = re.compile(r"^arn:(aws[\w-]*):sts::(\d{12}):assumed-role/([^/]+)/(.+)$")
_IAM = re.compile(r"^arn:(aws[\w-]*):iam::(\d{12}):(role|user)/(?:.*/)?([^/]+)$")


def _doc(d):
    """Policy documents arrive as dicts (boto3), JSON strings, or URL-encoded JSON (some CLI paths)."""
    if isinstance(d, dict):
        return d
    if isinstance(d, str):
        s = d if d.lstrip().startswith("{") else unquote(d)
        return json.loads(s)
    return {"Statement": []}


def _statements(name: str, doc) -> list[tuple[str, dict]]:
    return [(name, st) for st in as_list(_doc(doc).get("Statement"))]


@dataclass(frozen=True)
class PrincipalRef:
    """A principal ARN as given on the command line, parsed."""

    given: str
    partition: str
    account: str
    kind: str  # role | user
    name: str
    session_arn: str | None = None

    @property
    def iam_arn(self) -> str:
        """Best-effort IAM ARN (path unknown until resolved against GAAD)."""
        return f"arn:{self.partition}:iam::{self.account}:{self.kind}/{self.name}"


def parse_principal(arn: str) -> PrincipalRef:
    m = _ASSUMED.match(arn)
    if m:
        part, acct, role, _ = m.groups()
        return PrincipalRef(arn, part, acct, "role", role, session_arn=arn)
    m = _IAM.match(arn)
    if m:
        part, acct, kind, name = m.groups()
        return PrincipalRef(arn, part, acct, kind, name)
    raise ValueError(f"not an IAM role/user or STS assumed-role ARN: {arn}")


@dataclass
class Principal:
    ref: PrincipalRef
    arn: str  # resolved IAM ARN (with path when GAAD was available)
    statements: list[tuple[str, dict]] = field(default_factory=list)
    boundary: list[tuple[str, dict]] | None = None
    known: bool = True  # False: not found in any GAAD (e.g. principal lives in another account)

    @property
    def account(self) -> str:
        return self.ref.account

    @property
    def kind(self) -> str:
        return self.ref.kind


def find_principal(gaads: list[dict], ref: PrincipalRef) -> Principal:
    """Resolve `ref` against GAAD documents; returns an unknown principal when it isn't in any of them."""
    for data in gaads:
        managed: dict[str, dict] = {}
        for p in data.get("Policies", []):
            default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            if default:
                managed[p["Arn"]] = {"name": p.get("PolicyName", p["Arn"]), "doc": default.get("Document")}

        def attached(lst, managed=managed) -> list[tuple[str, dict]]:
            out = []
            for a in lst or []:
                m = managed.get(a.get("PolicyArn"))
                if m:
                    out += _statements(m["name"], m["doc"])
            return out

        def boundary(entity, managed=managed) -> list[tuple[str, dict]] | None:
            pb = entity.get("PermissionsBoundary")
            if not pb:
                return None
            m = managed.get(pb.get("PermissionsBoundaryArn"))
            # A boundary we can't see is treated as absent; that over-reports, which is the safe side for IR.
            return _statements(f"boundary:{m['name']}", m["doc"]) if m else None

        def same(entity_arn: str) -> bool:
            m = _IAM.match(entity_arn)
            return bool(m) and m.group(2) == ref.account and m.group(4) == ref.name

        if ref.kind == "role":
            for r in data.get("RoleDetailList", []):
                if same(r.get("Arn", "")) and r.get("RoleName") == ref.name:
                    st = attached(r.get("AttachedManagedPolicies"))
                    for ip in r.get("RolePolicyList", []):
                        st += _statements(ip["PolicyName"], ip.get("PolicyDocument"))
                    return Principal(ref, r["Arn"], st, boundary(r))
        else:
            groups = {}
            for g in data.get("GroupDetailList", []):
                st = attached(g.get("AttachedManagedPolicies"))
                for ip in g.get("GroupPolicyList", []):
                    st += _statements(f"{g['GroupName']}/{ip['PolicyName']}", ip.get("PolicyDocument"))
                groups[g["GroupName"]] = st
            for u in data.get("UserDetailList", []):
                if same(u.get("Arn", "")) and u.get("UserName") == ref.name:
                    st = attached(u.get("AttachedManagedPolicies"))
                    for ip in u.get("UserPolicyList", []):
                        st += _statements(ip["PolicyName"], ip.get("PolicyDocument"))
                    for g in u.get("GroupList", []):
                        st += groups.get(g, [])
                    return Principal(ref, u["Arn"], st, boundary(u))
    return Principal(ref, ref.iam_arn, [], None, known=False)


def load_scps(data) -> list[tuple[str, dict]]:
    """Accept a policy document, a list of documents, or `{"Policies": [{"Name"/"PolicySummary", "Content"}]}`."""
    out: list[tuple[str, dict]] = []
    if isinstance(data, dict) and "Statement" in data:
        return _statements("scp", data)
    items = data.get("Policies", []) if isinstance(data, dict) else as_list(data)
    for i, item in enumerate(items):
        if isinstance(item, dict) and "Statement" in item:
            out += _statements(f"scp#{i}", item)
            continue
        if isinstance(item, dict):
            name = item.get("Name") or (item.get("PolicySummary") or {}).get("Name") or f"scp#{i}"
            content = item.get("Content") or item.get("Document")
            if content:
                out += _statements(f"scp:{name}", content)
    return out
