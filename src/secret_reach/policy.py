"""Minimal IAM policy evaluator for one question: may principal P perform action A on resource R?

Supports Allow/Deny, Action/NotAction, Resource/NotResource, Principal/NotPrincipal, `*` and `?` wildcards.
Conditions are not evaluated: an Allow that depends on a Condition makes the result "conditional", and a
Deny with a Condition is recorded as "might block" (also conditional) instead of being applied.

How the pieces combine (same account vs. cross account, permission boundaries, SCPs, KMS key policies) lives in
`reach.py`; this module only answers "what does this set of statements say?".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache


def as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


@lru_cache(maxsize=4096)
def _rx(pattern: str, case_insensitive: bool) -> re.Pattern:
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{body}$", (re.I if case_insensitive else 0) | re.S)


def action_matches(pattern: str, action: str) -> bool:
    return bool(_rx(str(pattern), True).match(action))


def resource_matches(pattern: str, arn: str) -> bool:
    return bool(_rx(str(pattern), False).match(arn))


@dataclass(frozen=True)
class Who:
    """The principal being evaluated, as resource policies see it."""

    arn: str  # IAM role/user ARN (normalised from an assumed-role ARN)
    account: str
    aliases: tuple[str, ...] = ()  # other ARNs that identify the same caller (e.g. the STS session ARN)

    def match(self, principal) -> str | None:
        """Return "direct" if a Principal element names this caller (or "*"), "account" if it names its account."""
        if principal == "*":
            return "direct"
        if not isinstance(principal, dict):
            return None
        best = None
        for v in as_list(principal.get("AWS")):
            v = str(v)
            if v == "*" or v == self.arn or v in self.aliases:
                return "direct"
            if v == self.account or re.fullmatch(rf"arn:aws[\w-]*:iam::{re.escape(self.account)}:root", v):
                best = "account"
        return best


@dataclass
class Verdict:
    """What a set of statements says about one (action, resource)."""

    allow: bool = False
    allow_conditional: bool = False
    allow_source: str = ""
    deny: bool = False
    deny_source: str = ""
    maybe_deny: list[str] = field(default_factory=list)  # Deny statements with an unevaluated Condition

    @property
    def conditional(self) -> bool:
        return (self.allow and self.allow_conditional) or bool(self.maybe_deny)


def _matches(stmt: dict, action: str, arn: str) -> bool:
    if "NotAction" in stmt:
        if any(action_matches(p, action) for p in as_list(stmt["NotAction"])):
            return False
    elif not any(action_matches(p, action) for p in as_list(stmt.get("Action"))):
        return False
    if "NotResource" in stmt:
        return not any(resource_matches(p, arn) for p in as_list(stmt["NotResource"]))
    if "Resource" not in stmt:
        return True  # resource policies may omit Resource; it then means "this resource"
    return any(resource_matches(p, arn) for p in as_list(stmt.get("Resource")))


def _principal_kind(stmt: dict, who: Who | None) -> str | None:
    """For resource policies: does the statement apply to `who`? None for identity policies (always applies)."""
    if who is None:
        return "direct"
    if "NotPrincipal" in stmt:
        return None if who.match(stmt["NotPrincipal"]) else "direct"
    return who.match(stmt.get("Principal"))


def evaluate(
    statements: list[tuple[str, dict]], action: str, arn: str, who: Who | None = None, *, kind: str = "direct"
) -> Verdict:
    """Evaluate (policy_name, statement) pairs.

    `who` is given for resource-based policies (Principal must match). `kind` selects which Allow statements count:
    "direct" = statements naming the principal itself (or "*"), "account" = statements naming its account.
    Denies count for any principal match.
    """
    v = Verdict()
    for name, st in statements:
        if not isinstance(st, dict) or not _matches(st, action, arn):
            continue
        pk = _principal_kind(st, who)
        if pk is None:
            continue
        cond = bool(st.get("Condition"))
        name = f"{name}/{st['Sid']}" if st.get("Sid") else name
        if st.get("Effect") == "Deny":
            if cond:
                v.maybe_deny.append(name)
            elif not v.deny:
                v.deny, v.deny_source = True, name
        elif st.get("Effect") == "Allow" and pk == kind:
            if not v.allow or (v.allow_conditional and not cond):
                v.allow, v.allow_conditional, v.allow_source = True, cond, name
    return v


def any_allow_with_prefix(statements: list[tuple[str, dict]], action: str, prefix: str, who: Who | None = None) -> str | None:
    """Name of an Allow statement granting `action` on some resource under `prefix` (e.g. one S3 key prefix)."""
    for name, st in statements:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or "NotResource" in st:
            continue
        if who is not None and _principal_kind(st, who) != "direct":
            continue
        acts = as_list(st.get("Action"))
        if "NotAction" in st or not any(action_matches(p, action) for p in acts):
            continue
        if any(str(r).startswith(prefix) for r in as_list(st.get("Resource"))):
            return name
    return None


def statements_of(name: str, doc) -> list[tuple[str, dict]]:
    if not doc:
        return []
    return [(name, st) for st in as_list(doc.get("Statement"))]
