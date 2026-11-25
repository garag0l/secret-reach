"""SQL that shows which of the reachable resources the principal actually read (CloudTrail Lake or Athena).

All the read events used here are CloudTrail management events and are logged by default, except S3 GetObject,
which is a data event and only appears if S3 data events were enabled for the bucket.
"""

from __future__ import annotations

from datetime import date, datetime

from .inventory import CODEBUILD, EC2, ECS, LAMBDA, S3, SECRET, SSM
from .reach import NOT_READABLE, Result

# eventName -> requestParameters key that identifies the resource ('' = list/batch call, shown unfiltered)
EVENTS: dict[str, list[tuple[str, str]]] = {
    SECRET: [("GetSecretValue", "secretId"), ("BatchGetSecretValue", "")],
    SSM: [("GetParameter", "name"), ("GetParameters", ""), ("GetParametersByPath", ""), ("GetParameterHistory", "name")],
    LAMBDA: [
        ("GetFunctionConfiguration20150331v2", "functionName"),
        ("GetFunction20150331v2", "functionName"),
        ("ListFunctions20150331", ""),
    ],
    ECS: [("DescribeTaskDefinition", "taskDefinition")],
    CODEBUILD: [("BatchGetProjects", "")],
    S3: [("GetObject", "bucketName")],
    EC2: [("DescribeInstanceAttribute", "instanceId")],
}
SOURCES = {
    SECRET: "secretsmanager.amazonaws.com",
    SSM: "ssm.amazonaws.com",
    LAMBDA: "lambda.amazonaws.com",
    ECS: "ecs.amazonaws.com",
    CODEBUILD: "codebuild.amazonaws.com",
    S3: "s3.amazonaws.com",
    EC2: "ec2.amazonaws.com",
}


def parse_since(s: str) -> str:
    """Accept YYYY-MM-DD or an ISO timestamp; return 'YYYY-MM-DD HH:MM:SS' (UTC)."""
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        d = datetime.combine(date.fromisoformat(s), datetime.min.time())
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _identifiers(r: Result) -> list[str]:
    if r.type == EC2:
        return [r.arn.rsplit("/", 1)[-1]]
    if r.type == ECS:
        return [r.arn, r.arn.rsplit("/", 1)[-1], r.name]
    return [r.name, r.arn]


def query(principal_arns: list[str], results: list[Result], since: str, dialect: str = "lake", source: str | None = None) -> str:
    """dialect 'lake': CloudTrail Lake (event data store id in FROM); 'athena': table from the CloudTrail console template."""
    reach = [r for r in results if r.status != NOT_READABLE]
    ts = parse_since(since)
    if dialect == "lake":
        src = source or "<event-data-store-id>"

        def param(k):
            return f"element_at(requestParameters, {_q(k)})"

        who = " OR ".join(
            f"userIdentity.arn = {_q(a)} OR userIdentity.sessionContext.sessionIssuer.arn = {_q(a)}" for a in principal_arns
        )
        time_cond = f"eventTime >= {_q(ts)}"
        cols = "eventTime, eventSource, eventName, awsRegion, sourceIPAddress, userIdentity.arn AS caller, errorCode"
    else:
        src = source or "cloudtrail_logs"

        def param(k):
            return f"json_extract_scalar(requestparameters, {_q('$.' + k)})"

        who = " OR ".join(
            f"useridentity.arn = {_q(a)} OR useridentity.sessioncontext.sessionissuer.arn = {_q(a)}" for a in principal_arns
        )
        time_cond = f"from_iso8601_timestamp(eventtime) >= timestamp {_q(ts)}"
        cols = "eventtime, eventsource, eventname, awsregion, sourceipaddress, useridentity.arn AS caller, errorcode"

    ev = "eventName" if dialect == "lake" else "eventname"
    es = "eventSource" if dialect == "lake" else "eventsource"
    clauses = []
    keys = []
    for t in EVENTS:
        rs = [r for r in reach if r.type == t]
        if not rs:
            continue
        ids = sorted({i for r in rs for i in _identifiers(r)})
        for name, key in EVENTS[t]:
            base = f"({es} = {_q(SOURCES[t])} AND {ev} = {_q(name)}"
            if key:
                keys.append(key)
                clauses.append(base + f" AND {param(key)} IN ({', '.join(_q(i) for i in ids)}))")
            else:
                clauses.append(base + ")")
    if not clauses:
        return "-- no reachable resources: nothing to query"
    resource = "COALESCE(" + ", ".join(param(k) for k in dict.fromkeys(keys)) + ")" if keys else "NULL"
    lines = [
        f"-- secret-reach: reads of reachable secret-bearing resources by the principal since {ts} UTC ({dialect})",
        "-- Batch/list calls (GetParameters, BatchGetSecretValue, ListFunctions, BatchGetProjects) are not filtered by resource.",
        f"SELECT {cols}, {resource} AS resource",
        f"FROM {src}",
        f"WHERE {time_cond}",
        f"  AND ({who})",
        "  AND (",
        "       " + "\n    OR ".join(clauses),
        "  )",
        f"ORDER BY {'eventTime' if dialect == 'lake' else 'eventtime'}",
    ]
    return "\n".join(lines) + ";"
