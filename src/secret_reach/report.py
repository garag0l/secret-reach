"""Render results as a rotation checklist (text), JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
from itertools import groupby

from . import __version__
from .reach import CONDITIONAL, NOT_READABLE, READABLE, Result


def summary(results: list[Result]) -> dict:
    return {s: sum(1 for r in results if r.status == s) for s in (READABLE, CONDITIONAL, NOT_READABLE)}


def _action(r: Result) -> str:
    if r.exposure and r.type in ("lambda-env", "ecs-task-definition", "codebuild-env"):
        names = ", ".join(r.exposure[:4]) + (f", +{len(r.exposure) - 4}" if len(r.exposure) > 4 else "")
        return f"{r.action} [{names}]"
    if r.type == "ssm-parameter" and r.exposure:
        return f"{r.action} [{r.exposure[0]}]"
    return r.action


def text(results: list[Result], meta: dict, show_all: bool = False, color: bool = False) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    col = {READABLE: "31", CONDITIONAL: "33", NOT_READABLE: "2"}
    lines = [
        c("1", f"secret-reach {__version__}") + f"  principal {meta['principal']}",
        f"source: {meta['source']}  account {meta['account']}"
        + (f"  regions {','.join(meta['regions'])}" if meta.get("regions") else ""),
    ]
    if not meta.get("principal_known", True):
        lines.append(c("33", "note: principal not found in the IAM data; identity policies assumed to allow (worst case)"))
    lines.append("")
    shown = [r for r in results if show_all or r.status != NOT_READABLE]
    shown.sort(
        key=lambda r: (
            r.owner == "(no owner tag)",
            r.owner,
            {READABLE: 0, CONDITIONAL: 1}.get(r.status, 2),
            r.type,
            r.region,
            r.name,
        )
    )
    if not shown:
        lines.append("Nothing secret-bearing is readable by this principal.")
    w_name = min(max([len(r.name) for r in shown] + [4]), 48)
    for owner, group in groupby(shown, key=lambda r: r.owner):
        lines.append(c("1", f"owner: {owner}"))
        lines.append(c("2", f"  {'STATUS':<13} {'TYPE':<22} {'REGION':<15} {'NAME':<{w_name}}  ACTION"))
        for r in group:
            name = r.name if len(r.name) <= w_name else r.name[: w_name - 1] + "~"
            lines.append(f"  {c(col[r.status], f'{r.status:<13}')} {r.type:<22} {r.region:<15} {name:<{w_name}}  {_action(r)}")
        lines.append("")
    notes = [r for r in shown if r.status == CONDITIONAL or (r.status == NOT_READABLE and show_all)]
    if notes:
        lines.append(c("1", "Why conditional / not readable"))
        for r in notes:
            lines.append(f"  {r.type} {r.name}: {'; '.join(r.reasons) or 'see granted_by'}")
        lines.append("")
    for m in meta.get("simulator_mismatches") or []:
        lines.append(c("33", f"simulator: {m}"))
    for e in meta.get("errors") or []:
        lines.append(c("33", f"collection error: {e}"))
    s = summary(results)
    lines.append(
        c("1", f"{s[READABLE]} readable, {s[CONDITIONAL]} conditional")
        + f", {s[NOT_READABLE]} not readable"
        + ("" if show_all or not s[NOT_READABLE] else " (--all lists them with the reason)")
    )
    return "\n".join(lines)


def as_json(results: list[Result], meta: dict, show_all: bool = True) -> str:
    out = {
        "version": __version__,
        **meta,
        "summary": summary(results),
        "results": [r.to_dict() for r in results if show_all or r.status != NOT_READABLE],
    }
    return json.dumps(out, indent=2)


CSV_FIELDS = [
    "status",
    "owner",
    "type",
    "region",
    "name",
    "arn",
    "action",
    "exposure",
    "granted_by",
    "reasons",
    "kms_key",
    "simulator",
]


def as_csv(results: list[Result], show_all: bool = True) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for r in results:
        if not show_all and r.status == NOT_READABLE:
            continue
        d = r.to_dict()
        w.writerow({k: "; ".join(d[k]) if isinstance(d[k], list) else ("" if d[k] is None else d[k]) for k in CSV_FIELDS})
    return buf.getvalue()
