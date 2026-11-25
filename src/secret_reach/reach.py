"""Decide, for every secret-bearing resource in an inventory, whether a principal can read it.

Combination rules (a simplified version of the AWS policy evaluation logic):

* Any matching explicit Deny (SCP, identity policy, permission boundary, resource policy, key policy) wins.
* SCPs (only with --scp-export): must allow the action when they contain any Allow statement.
* Same account, normal resource: allowed when the identity policy allows (within the permission boundary), or the
  resource policy names the principal directly (a resource-policy grant to a role ARN is still limited by the
  role's boundary; a grant to a user ARN is not).
* Cross account: the identity policy must allow AND the resource policy must name the principal or its account.
* KMS: the key policy is always required. Same account: it names the principal directly, or it names the account
  (`:root`, which delegates to IAM) and the identity policy allows kms:Decrypt. AWS managed keys
  (`aws/secretsmanager`, `aws/ssm`, `aws/lambda`, ...) work for any principal of the same account that can call the
  service, and never cross account.

Anything resting on an unevaluated Condition, an unknown key policy, or an unknown identity (principal from another
account with no GAAD supplied) is reported as "conditional": treat it as readable until proven otherwise.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .iam import Principal
from .inventory import CODEBUILD, EC2, ECS, LAMBDA, S3, SECRET, SSM, ssm_parameter_arn, ssm_path_arns
from .policy import Verdict, Who, any_allow_with_prefix, evaluate, statements_of

READABLE, CONDITIONAL, NOT_READABLE = "readable", "conditional", "not-readable"
STATUS_ORDER = {READABLE: 0, CONDITIONAL: 1, NOT_READABLE: 2}


@dataclass
class Access:
    ok: bool
    conditional: bool = False
    via: str = ""
    why: str = ""
    identity_ok: bool | None = None  # identity policy + boundary alone (for the simulator cross-check)
    notes: list[str] = field(default_factory=list)


@dataclass
class Context:
    principal: Principal
    scps: list[tuple[str, dict]] | None = None

    @property
    def who(self) -> Who:
        p = self.principal
        aliases = tuple(a for a in (p.ref.session_arn, p.ref.given) if a and a != p.arn)
        return Who(p.arn, p.account, aliases)


def check(
    ctx: Context, action: str, arn: str, resource_policy: list[tuple[str, dict]] | None, resource_account: str, *, kms=False
) -> Access:
    p = ctx.principal
    notes: list[str] = []
    cond = False

    def maybe(v: Verdict, label: str) -> None:
        nonlocal cond
        if v.maybe_deny:
            cond = True
            notes.append(f"{label} has a conditional Deny ({', '.join(sorted(set(v.maybe_deny)))})")

    if ctx.scps is not None:
        s = evaluate(ctx.scps, action, arn)
        if s.deny:
            return Access(False, why=f"SCP {s.deny_source} denies {action}")
        if any(st.get("Effect") == "Allow" for _, st in ctx.scps) and not s.allow:
            return Access(False, why=f"no SCP allows {action}")
        maybe(s, "SCP")
        cond |= s.allow_conditional

    ident = evaluate(p.statements, action, arn)
    if ident.deny:
        return Access(False, why=f"identity policy {ident.deny_source} denies {action}", identity_ok=False)
    maybe(ident, "identity policy")
    bnd = evaluate(p.boundary, action, arn) if p.boundary is not None else None
    if bnd is not None:
        if bnd.deny:
            return Access(False, why=f"permission boundary denies {action}", identity_ok=False)
        maybe(bnd, "permission boundary")
    boundary_ok = bnd is None or bnd.allow
    boundary_cond = bool(bnd and bnd.allow_conditional)

    if p.known:
        identity_ok = ident.allow and boundary_ok
        identity_cond = ident.allow_conditional or boundary_cond
    else:
        identity_ok, identity_cond = True, True
        notes.append("identity policies unknown (principal not in the IAM data); assumed to allow")

    rp = resource_policy or []
    label = "key policy" if kms else "resource policy"
    direct = evaluate(rp, action, arn, ctx.who, kind="direct")
    if direct.deny:
        return Access(False, why=f"{label} denies {action}", identity_ok=identity_ok)
    acct = evaluate(rp, action, arn, ctx.who, kind="account")
    maybe(direct, label)
    direct_ok = direct.allow and (p.kind == "user" or boundary_ok)
    same = resource_account == p.account

    def done(ok: bool, c: bool, via: str, why: str = "") -> Access:
        if ok and c:
            notes.append(f"{action} is allowed only under a Condition ({via}); not evaluated")
        return Access(ok, conditional=ok and (c or cond), via=via, why=why, identity_ok=identity_ok, notes=notes if ok else [])

    if same and not kms:
        if identity_ok:
            return done(True, identity_cond, f"identity:{ident.allow_source}" if p.known else "identity:assumed")
        if direct_ok:
            return done(True, direct.allow_conditional or (p.kind == "role" and boundary_cond), direct.allow_source)
        if direct.allow and not boundary_ok:
            return done(False, False, "", f"{label} allows {action} but the permission boundary does not")
        if ident.allow and not boundary_ok:
            return done(False, False, "", f"permission boundary does not allow {action}")
        return done(False, False, "", f"no policy allows {action}")

    # KMS (any account) and cross-account resources: the resource/key policy must trust the caller.
    if direct_ok:
        if same:  # direct key-policy grant in the same account needs no identity policy
            return done(True, direct.allow_conditional or (p.kind == "role" and boundary_cond), direct.allow_source)
        if identity_ok:
            return done(True, identity_cond or direct.allow_conditional, direct.allow_source)
    if acct.allow and identity_ok:
        idv = f"identity:{ident.allow_source}" if p.known else "identity:assumed"
        return done(True, identity_cond or acct.allow_conditional, f"{acct.allow_source} (account) + {idv}")
    if not rp:
        return done(False, False, "", f"{label} not available or empty")
    if (direct.allow or acct.allow) and not identity_ok:
        return done(False, False, "", f"{label} trusts the account but the identity policy does not allow {action}")
    return done(False, False, "", f"{label} does not allow {action} for this principal")


@dataclass
class Result:
    type: str
    name: str
    arn: str
    region: str
    account: str
    owner: str
    status: str
    action: str
    exposure: list[str] = field(default_factory=list)  # env var names, parameter type, ... never values
    granted_by: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    kms_key: str | None = None
    checked: list[str] = field(default_factory=list)
    simulator: str | None = None
    # for --simulate
    primary_action: str = ""
    primary_resource: str = ""
    identity_ok: bool | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in ("primary_action", "primary_resource", "identity_ok"):
            d.pop(k)
        return d


def _owner(tags: dict, keys: list[str]) -> str:
    lower = {str(k).lower(): v for k, v in (tags or {}).items()}
    for k in keys:
        if lower.get(k.lower()):
            return str(lower[k.lower()])
    return "(no owner tag)"


def _alternatives(r: dict, partition: str) -> list[tuple[str, str, bool]]:
    """(action, resource ARN, resource-policy applies) pairs; reading via any of them exposes the value."""
    t, arn = r["type"], r["arn"]
    if t == SECRET:
        return [("secretsmanager:GetSecretValue", arn, True)]
    if t == SSM:
        acct = arn.split(":")[4]
        exact = ssm_parameter_arn(partition, r["region"], acct, r["name"])
        alts = [(a, exact, False) for a in ("ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory")]
        return alts + [("ssm:GetParametersByPath", p, False) for p in ssm_path_arns(partition, r["region"], acct, r["name"])]
    if t == LAMBDA:
        return [
            ("lambda:GetFunctionConfiguration", arn, True),
            ("lambda:GetFunction", arn, True),
            ("lambda:ListFunctions", "*", False),
        ]
    if t == ECS:
        return [("ecs:DescribeTaskDefinition", arn, False)]
    if t == CODEBUILD:
        return [("codebuild:BatchGetProjects", arn, False)]
    if t == S3:
        return [("s3:GetObject", f"{arn}/*", True)]
    if t == EC2:
        return [("ec2:DescribeInstanceAttribute", arn, False)]
    raise ValueError(t)


def _needs_kms(r: dict) -> bool:
    if r["type"] in (SECRET, LAMBDA):
        return True
    if r["type"] == SSM:
        return (r.get("details") or {}).get("parameter_type") == "SecureString"
    if r["type"] == S3:
        return bool(r.get("kms_key"))
    return False


def _action_text(r: dict) -> str:
    d = r.get("details") or {}
    t = r["type"]
    if t == SECRET:
        return "rotate secret"
    if t == SSM:
        if d.get("parameter_type") == "SecureString":
            return "rotate parameter value"
        return "rotate value; re-create as SecureString (re-encrypt)"
    if t == LAMBDA:
        return "rotate Lambda env values"
    if t in (ECS, CODEBUILD):
        if d.get("plaintext_env"):
            return "rotate plaintext env values, then move them to secrets (re-encrypt)"
        return "no plaintext values (only references; rotate those if listed)"
    if t == S3:
        return "review objects (state/backups); rotate credentials found in them"
    if t == EC2:
        return "review user data; rotate any credentials in it"
    return "rotate"


def _exposure(r: dict) -> list[str]:
    d = r.get("details") or {}
    t = r["type"]
    if t == SSM:
        return [d.get("parameter_type", "?")]
    if t == LAMBDA:
        return list(d.get("env_names", []))
    if t in (ECS, CODEBUILD):
        return list(d.get("plaintext_env", [])) + [f"{n} (ref)" for n in d.get("secret_refs", [])]
    if t == S3:
        return [f"name matches {d.get('matched', 'pattern')}"]
    if t == EC2:
        return ["user data not inspected"]
    return []


def _merge(reasons: list[str]) -> list[str]:
    """Collapse 'no policy allows X' for several alternative actions into one line."""
    reasons = list(dict.fromkeys(filter(None, reasons)))
    none = [r.removeprefix("no policy allows ") for r in reasons if r.startswith("no policy allows ")]
    rest = [r for r in reasons if not r.startswith("no policy allows ")]
    return rest + ([f"no policy allows {' / '.join(none)}"] if none else [])


def _rank(a: Access) -> int:
    return 0 if a.ok and not a.conditional else 1 if a.ok else 2


def kms_access(ctx: Context, inv: dict, r: dict) -> Access:
    key = r.get("kms_key")
    res_acct = r["arn"].split(":")[4] or inv.get("account", "")
    same = ctx.principal.account == (res_acct or inv.get("account"))
    if not key:
        if same:
            return Access(True, via="kms:aws-managed")
        return Access(False, why="AWS managed KMS key cannot be used from another account")
    info = (inv.get("kms_keys") or {}).get(key)
    if info is None:
        return Access(True, conditional=True, via="kms:unknown", notes=[f"KMS key {key} not described in the inventory"])
    if info.get("manager") == "AWS":
        if same:
            return Access(True, via="kms:aws-managed")
        return Access(False, why="AWS managed KMS key cannot be used from another account")
    if not info.get("policy"):
        return Access(True, conditional=True, via="kms:policy-unknown", notes=[f"key policy of {key} not available"])
    key_acct = key.split(":")[4] if key.startswith("arn:") else inv.get("account", "")
    a = check(ctx, "kms:Decrypt", key, statements_of("key policy", info["policy"]), key_acct, kms=True)
    if not a.ok:
        a.why = f"CMK {key}: {a.why}"
    return a


def evaluate_inventory(ctx: Context, inv: dict, owner_tags: list[str] | None = None) -> list[Result]:
    owner_tags = owner_tags or ["owner", "team"]
    partition = inv.get("partition", "aws")
    out: list[Result] = []
    for r in inv["resources"]:
        res_acct = r["arn"].split(":")[4] if r["arn"].count(":") >= 5 and r["arn"].split(":")[4] else inv["account"]
        rp = statements_of("resource policy", r.get("resource_policy"))
        best: Access | None = None
        best_alt = None
        reasons: list[str] = []
        for action, arn, rp_applies in _alternatives(r, partition):
            a = check(ctx, action, arn, rp if rp_applies else None, res_acct)
            if not a.ok and r["type"] == S3:
                pref = any_allow_with_prefix(ctx.principal.statements, action, f"{r['arn']}/") or any_allow_with_prefix(
                    rp, action, f"{r['arn']}/", ctx.who
                )
                if pref:
                    a = Access(
                        True,
                        conditional=True,
                        via=f"prefix:{pref}",
                        identity_ok=a.identity_ok,
                        notes=["access to part of the bucket"],
                    )
            if not a.ok:
                reasons.append(a.why)
            if best is None or _rank(a) < _rank(best):
                best, best_alt = a, (action, arn)
        assert best is not None and best_alt is not None
        status = NOT_READABLE
        granted: list[str] = []
        notes = list(best.notes)
        if best.ok:
            status = CONDITIONAL if best.conditional else READABLE
            granted.append(f"{best_alt[0]} via {best.via}")
            if _needs_kms(r):
                k = kms_access(ctx, inv, r)
                if not k.ok:
                    status = NOT_READABLE
                    reasons = [k.why]
                    granted = []
                    notes = []
                else:
                    granted.append(f"kms:Decrypt via {k.via}")
                    notes += k.notes
                    if k.conditional:
                        status = CONDITIONAL
        out.append(
            Result(
                type=r["type"],
                name=r["name"],
                arn=r["arn"],
                region=r["region"],
                account=res_acct,
                owner=_owner(r.get("tags") or {}, owner_tags),
                status=status,
                action=_action_text(r),
                exposure=_exposure(r),
                granted_by=granted,
                reasons=(notes if status != NOT_READABLE else _merge(reasons)),
                kms_key=r.get("kms_key"),
                checked=list(dict.fromkeys(a for a, _, _ in _alternatives(r, partition))),
                primary_action=best_alt[0],
                primary_resource=best_alt[1],
                identity_ok=best.identity_ok,
            )
        )
    out.sort(key=lambda x: (STATUS_ORDER[x.status], x.owner, x.type, x.region, x.name))
    return out
