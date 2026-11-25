"""secret-reach must never read a secret value. These tests fail the build if code that could do so appears.

Static: scan the AST of every module for calls that return secret values (GetSecretValue, GetParameter*,
GetFunction*, DescribeInstanceAttribute/user data, GetObject, kms Decrypt, ...), any `WithDecryption`
keyword, dynamic lookups of those names via strings, and, in the collector, any access to a `value`/`Value` field
or `.values()`/`.items()` iteration (env var values would come from there).
Runtime: tests/test_live.py seeds marked fake values into moto and asserts they appear in no output.
"""

import ast
from pathlib import Path

import pytest

from secret_reach.collect import ALLOWED_CALLS, dry_run_lines

SRC = Path(__file__).parent.parent / "src" / "secret_reach"
FILES = sorted(SRC.glob("*.py"))

BANNED_METHODS = {
    "get_secret_value",
    "batch_get_secret_value",
    "get_parameter",
    "get_parameters",
    "get_parameters_by_path",
    "get_parameter_history",
    "get_function",
    "get_function_configuration",
    "describe_instance_attribute",
    "describe_launch_template_versions",
    "get_launch_template_data",
    "get_object",
    "download_file",
    "download_fileobj",
    "decrypt",
    "get_object_attributes",
    "select_object_content",
}
BANNED_OPERATIONS = {
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "ssm:GetParameterHistory",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "ec2:DescribeInstanceAttribute",
    "s3:GetObject",
    "kms:Decrypt",
}


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_value_reading_calls(path):
    bad = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in BANNED_METHODS:
                bad.append(f"line {node.lineno}: call to {name}()")
            for kw in node.keywords:
                if kw.arg == "WithDecryption":
                    bad.append(f"line {node.lineno}: WithDecryption keyword")
            if name in ("getattr", "get_paginator") and any(
                isinstance(a, ast.Constant) and a.value in BANNED_METHODS for a in node.args
            ):
                bad.append(f"line {node.lineno}: dynamic lookup of a banned method")
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in BANNED_METHODS | {"WithDecryption"}:
            bad.append(f"line {node.lineno}: string {node.value!r}")
        if isinstance(node, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "WithDecryption" for k in node.keys):
            bad.append(f"line {node.lineno}: WithDecryption in a dict")
    assert not bad, f"{path.name} could read secret values:\n" + "\n".join(bad)


def test_collector_never_touches_value_fields():
    bad = []
    for node in ast.walk(_tree(SRC / "collect.py")):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and str(node.slice.value).lower() in ("value", "secretstring", "secretbinary", "userdata")
        ):
            bad.append(f"line {node.lineno}: [{node.slice.value!r}]")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).lower() in ("value", "secretstring", "secretbinary", "userdata")
            ):
                bad.append(f"line {node.lineno}: .get({node.args[0].value!r})")
            if node.func.attr in ("values", "items"):
                bad.append(f"line {node.lineno}: .{node.func.attr}()")
    assert not bad, "collect.py reads value fields:\n" + "\n".join(bad)


def test_scanner_catches_a_planted_call(tmp_path):
    """Guard against the scan silently passing: a module that calls get_secret_value must be caught."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def f(c):\n    return c.get_secret_value(SecretId='x')\n\ndef g(s):\n    return s.get_parameter(Name='n', WithDecryption=True)\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="get_secret_value"):
        test_no_value_reading_calls(planted)


def test_documented_calls_exclude_value_apis():
    assert not (ALLOWED_CALLS & BANNED_OPERATIONS)
    text = "\n".join(dry_run_lines(None))
    for op in BANNED_OPERATIONS:
        assert not any(line.split()[0] == op for line in text.splitlines() if line and not line.startswith("#"))
