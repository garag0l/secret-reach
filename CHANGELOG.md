# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- `secret-reach --principal ARN` lists every secret-bearing resource the principal can read, grouped by owner tag and
  type, with the action needed (rotate secret, rotate Lambda env values, rotate plaintext env values and re-encrypt,
  review state/backups, review user data).
- Resource types: Secrets Manager secrets, SSM parameters (SecureString, plus String parameters whose names look like
  secrets), Lambda functions with environment variables (names only), ECS task definitions (plaintext env and
  `secrets` references), CodeBuild project environment variables, S3 buckets whose names match Terraform-state/backup
  patterns, and EC2 instances (user data flagged, never read).
- Local policy evaluator: identity policies, permission boundaries, resource policies (secret, bucket, Lambda function
  policy), KMS key policies for customer-managed keys, AWS managed keys, same-account vs. cross-account rules,
  Allow/Deny, NotAction/NotResource, Principal/NotPrincipal. Results that rest on an unevaluated Condition are
  reported as `conditional`.
- Optional `--scp-export FILE` (SCPs applied to the principal's account) and `--simulate` (cross-check with
  `iam:SimulatePrincipalPolicy` in live mode).
- Input modes: `--live` (read-only boto3, all enabled regions or `--regions`) and offline `--inventory FILE`;
  `secret-reach snapshot -o FILE` writes the offline inventory, which never contains secret values. `--dry-run`
  prints every API call that would be made.
- Output: text checklist, `--format json|csv`, and `--since DATE` CloudTrail Lake / Athena SQL listing which of the
  reachable resources the principal actually read.
- Tests: moto-backed collection of every resource type, offline evaluator cases (including the golden
  "GetSecretValue on `*` but the CMK key policy doesn't allow decrypt" case), and a no-secret-values test that scans
  the source AST and checks that seeded values never reach any output.
