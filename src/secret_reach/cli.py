"""secret-reach command line.

secret-reach --principal ARN (--inventory FILE | --live) [options]   rotation checklist
secret-reach snapshot --out FILE [--regions ...]                     write an offline inventory from live AWS
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .cloudtrail import query as ct_query
from .collect import dry_run_lines
from .iam import find_principal, load_scps, parse_principal
from .inventory import InventoryError, load, save
from .reach import Context, evaluate_inventory
from .report import as_csv, as_json, text


def _regions(s: str | None) -> list[str] | None:
    if not s or s == "all":
        return None
    return [r.strip() for r in s.split(",") if r.strip()]


def _session(profile: str | None):
    try:
        import boto3
    except ImportError:
        print("live mode needs boto3: pip install 'secret-reach[live]'", file=sys.stderr)
        return None
    return boto3.session.Session(profile_name=profile)


def _live_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", help="AWS profile for live mode")
    p.add_argument("--regions", default="all", help="comma-separated regions, or 'all' (enabled regions; default)")
    p.add_argument("--workers", type=int, default=8, help="regions collected in parallel (default 8)")
    p.add_argument("--dry-run", action="store_true", help="print the read-only API calls that would be made, then exit")


def snapshot_main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="secret-reach snapshot", description="Write an offline inventory (no secret values) from live AWS."
    )
    p.add_argument("-o", "--out", required=True, metavar="FILE")
    _live_args(p)
    a = p.parse_args(argv)
    if a.dry_run:
        print("\n".join(dry_run_lines(_regions(a.regions))))
        return 0
    session = _session(a.profile)
    if session is None:
        return 2
    from .collect import collect

    inv = collect(session, _regions(a.regions), a.workers)
    save(inv, a.out)
    print(
        f"wrote {a.out}: {len(inv['resources'])} resources in {len(inv['regions'])} region(s), {len(inv['errors'])} error(s)",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "snapshot":
        return snapshot_main(argv[1:])

    p = argparse.ArgumentParser(
        prog="secret-reach",
        description="List every secret-bearing AWS resource a (compromised) principal can read, as a rotation checklist. "
        "Never reads secret values. Subcommand: `secret-reach snapshot -o FILE` writes an offline inventory.",
    )
    p.add_argument("--principal", required=False, metavar="ARN", help="IAM role/user ARN or STS assumed-role ARN")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--inventory", metavar="FILE", help="offline inventory written by `secret-reach snapshot`")
    src.add_argument("--live", action="store_true", help="collect the inventory now with your AWS credentials (read-only)")
    _live_args(p)
    p.add_argument(
        "--gaad",
        action="append",
        default=[],
        metavar="FILE",
        help="extra `aws iam get-account-authorization-details` "
        "output to find the principal in (e.g. its own account when it is cross-account); repeatable",
    )
    p.add_argument(
        "--scp-export",
        metavar="FILE",
        help="SCPs that apply to the principal's account (JSON policy, list, or {'Policies': [{'Name', 'Content'}]})",
    )
    p.add_argument(
        "--simulate", action="store_true", help="live mode: cross-check identity decisions with iam:SimulatePrincipalPolicy"
    )
    p.add_argument("--owner-tag", default="owner,team", help="tag key(s) used to group results (default: owner,team)")
    p.add_argument("--all", action="store_true", help="text output: also list resources that are not readable, with the reason")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("--since", metavar="DATE", help="also print a CloudTrail query for reads of these resources since DATE")
    p.add_argument("--query-dialect", choices=["lake", "athena"], default="lake", help="--since SQL dialect (default: lake)")
    p.add_argument("--query-source", metavar="NAME", help="event data store id (lake) or table name (athena) for --since")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    if a.dry_run:
        print("\n".join(dry_run_lines(_regions(a.regions))))
        if a.simulate:
            print("iam:SimulatePrincipalPolicy                per reachable-candidate resource (--simulate)")
        return 0
    if not a.principal or not (a.inventory or a.live):
        p.error("--principal and one of --inventory/--live are required")
    try:
        ref = parse_principal(a.principal)
    except ValueError as e:
        p.error(str(e))

    session = None
    try:
        if a.inventory:
            inv = load(a.inventory)
            source = a.inventory
        else:
            session = _session(a.profile)
            if session is None:
                return 2
            from .collect import collect

            inv = collect(session, _regions(a.regions), a.workers)
            source = "live"
    except (OSError, InventoryError, json.JSONDecodeError) as e:
        print(f"secret-reach: {e}", file=sys.stderr)
        return 2

    gaads = [inv.get("iam") or {}] + [json.loads(Path(g).read_text(encoding="utf-8-sig")) for g in a.gaad]
    principal = find_principal(gaads, ref)
    scps = load_scps(json.loads(Path(a.scp_export).read_text(encoding="utf-8-sig"))) if a.scp_export else None
    results = evaluate_inventory(Context(principal, scps), inv, [k.strip() for k in a.owner_tag.split(",") if k.strip()])

    mismatches: list[str] = []
    if a.simulate:
        if session is None:
            print("secret-reach: --simulate needs --live (it calls iam:SimulatePrincipalPolicy)", file=sys.stderr)
            return 2
        from .simulate import cross_check

        mismatches = cross_check(session, principal.arn, results)

    meta = {
        "principal": a.principal,
        "resolved_principal": principal.arn,
        "principal_known": principal.known,
        "source": source,
        "account": inv["account"],
        "regions": inv.get("regions") or [],
        "scps_applied": scps is not None,
        "errors": inv.get("errors") or [],
        "simulator_mismatches": mismatches,
    }
    arns = list(dict.fromkeys(x for x in (principal.arn, ref.given if ref.session_arn is None else None) if x))
    sql = ct_query(arns, results, a.since, a.query_dialect, a.query_source) if a.since else None

    if a.format == "json":
        if sql:
            meta["cloudtrail_query"] = {"dialect": a.query_dialect, "since": a.since, "sql": sql}
        out = as_json(results, meta)
    elif a.format == "csv":
        out = as_csv(results)
        if sql:
            print(sql, file=sys.stderr)
    else:
        color = not a.no_color and not a.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        out = text(results, meta, a.all, color)
        if sql:
            out += f"\n\nCloudTrail query (--since {a.since}):\n\n{sql}"
    if a.output:
        Path(a.output).write_text(out + "\n", encoding="utf-8", newline="\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
