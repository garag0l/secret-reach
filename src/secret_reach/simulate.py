"""Optional cross-check of the identity-side decision against iam:SimulatePrincipalPolicy (live mode, --simulate).

The simulator evaluates the principal's identity policies and permission boundary for one action on one resource.
It does not know about the KMS key policy or (without a caller ARN) the resource policy, so the comparison is made
against secret-reach's identity-side decision only. Disagreements are written into each result's `simulator` field
and listed in the report; the final status is not changed.
"""

from __future__ import annotations

from .reach import Result


def cross_check(session, principal_arn: str, results: list[Result], region: str | None = None) -> list[str]:
    iam = session.client("iam", region_name=region)
    mismatches: list[str] = []
    for r in results:
        if not r.primary_action or r.identity_ok is None:
            continue
        try:
            resp = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn, ActionNames=[r.primary_action], ResourceArns=[r.primary_resource]
            )
        except Exception as e:  # noqa: BLE001 - simulator is advisory
            r.simulator = f"error: {getattr(e, 'response', {}).get('Error', {}).get('Code') or type(e).__name__}"
            continue
        ev = (resp.get("EvaluationResults") or [{}])[0]
        decision = ev.get("EvalDecision", "unknown")
        missing = ev.get("MissingContextValues") or []
        r.simulator = decision + (" (missing context: " + ", ".join(missing) + ")" if missing else "")
        if (decision == "allowed") != bool(r.identity_ok) and not missing:
            mismatches.append(
                f"{r.type} {r.name}: simulator says {decision} for {r.primary_action}, local identity evaluation says "
                f"{'allowed' if r.identity_ok else 'not allowed'}"
            )
    return mismatches
