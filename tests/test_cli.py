import csv
import io
import json
from pathlib import Path

import pytest

from secret_reach.cli import main
from secret_reach.cloudtrail import parse_since, query

DEMO = str(Path(__file__).parent.parent / "examples" / "demo-inventory.json")
ROLE = "arn:aws:iam::111122223333:role/integrations/vendor-x-integration"


def test_text_report_groups_by_owner(capsys):
    assert main(["--principal", ROLE, "--inventory", DEMO, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "owner: payments" in out and "owner: api" in out
    assert "prod/db/master" not in out  # not readable: hidden without --all
    assert "7 readable, 1 conditional, 5 not readable" in out
    assert main(["--principal", ROLE, "--inventory", DEMO, "--all"]) == 0
    out = capsys.readouterr().out
    assert "prod/db/master" in out and "key policy does not allow kms:Decrypt" in out


def test_json_and_csv(capsys, tmp_path):
    assert main(["--principal", ROLE, "--inventory", DEMO, "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"] == {"readable": 7, "conditional": 1, "not-readable": 5}
    assert data["resolved_principal"] == ROLE
    out = tmp_path / "r.csv"
    assert main(["--principal", ROLE, "--inventory", DEMO, "-f", "csv", "-o", str(out)]) == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8"))))
    assert len(rows) == 13
    lam = next(r for r in rows if r["name"] == "billing-webhook")
    assert lam["exposure"] == "DB_URL; STRIPE_SECRET; LOG_LEVEL" and lam["action"] == "rotate Lambda env values"


def test_since_query_lake_and_athena(capsys):
    assert main(["--principal", ROLE, "--inventory", DEMO, "-f", "json", "--since", "2026-11-01"]) == 0
    sql = json.loads(capsys.readouterr().out)["cloudtrail_query"]["sql"]
    assert "FROM <event-data-store-id>" in sql
    assert "eventTime >= '2026-11-01 00:00:00'" in sql
    assert f"userIdentity.sessionContext.sessionIssuer.arn = '{ROLE}'" in sql
    assert "'prod/payments/stripe-api-key'" in sql and "GetSecretValue" in sql
    assert "'prod/db/master'" not in sql  # not readable: not in the query
    assert "GetFunctionConfiguration20150331v2" in sql and "'GetObject'" in sql
    assert (
        main(
            [
                "--principal",
                ROLE,
                "--inventory",
                DEMO,
                "--since",
                "2026-11-01T08:00:00Z",
                "--query-dialect",
                "athena",
                "--query-source",
                "ct_logs",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "FROM ct_logs" in out and "json_extract_scalar(requestparameters, '$.secretId')" in out
    assert "from_iso8601_timestamp(eventtime) >= timestamp '2026-11-01 08:00:00'" in out


def test_query_escapes_quotes_and_handles_nothing_reachable():
    assert parse_since("2026-11-01") == "2026-11-01 00:00:00"
    assert query(["arn:aws:iam::1:role/x'y"], [], "2026-11-01").startswith("-- no reachable")


def test_dry_run_needs_no_credentials(capsys):
    assert main(["--dry-run", "--regions", "us-east-1,eu-west-1"]) == 0
    out = capsys.readouterr().out
    assert "secretsmanager:ListSecrets" in out and "in us-east-1, eu-west-1" in out
    assert "ec2:DescribeRegions" not in out
    assert main(["snapshot", "-o", "x.json", "--dry-run"]) == 0
    assert "ec2:DescribeRegions" in capsys.readouterr().out


def test_errors(capsys, tmp_path):
    with pytest.raises(SystemExit):
        main(["--inventory", DEMO])
    with pytest.raises(SystemExit):
        main(["--principal", "arn:aws:s3:::bucket", "--inventory", DEMO])
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "format": "secret-reach/inventory@1",
                "account": "1",
                "resources": [{"type": "ssm-parameter", "arn": "a", "name": "n", "region": "r", "Value": "x"}],
            }
        ),
        encoding="utf-8",
    )
    assert main(["--principal", ROLE, "--inventory", str(bad)]) == 2
    assert "must not contain secret values" in capsys.readouterr().err
    assert main(["--principal", ROLE, "--inventory", DEMO, "--simulate"]) == 2


def test_scp_export_and_owner_tag(capsys, tmp_path):
    scp = tmp_path / "scp.json"
    scp.write_text(
        json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "secretsmanager:*", "Resource": "*"}]}),
        encoding="utf-8",
    )
    assert main(["--principal", ROLE, "--inventory", DEMO, "--scp-export", str(scp), "-f", "json", "--owner-tag", "team"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scps_applied"] is True
    assert all(r["status"] == "not-readable" for r in data["results"] if r["type"] == "secretsmanager-secret")
    assert {r["owner"] for r in data["results"]} == {"api", "(no owner tag)"}


def test_unknown_principal_warns(capsys):
    assert main(["--principal", "arn:aws:iam::444455556666:role/someone-else", "--inventory", DEMO, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "principal not found in the IAM data" in out
