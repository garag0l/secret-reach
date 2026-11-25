# secret-reach

**After an AWS role or access key is compromised, list every secret that principal could read, so you know exactly what to rotate. secret-reach never reads a secret value.**

[![CI](https://github.com/garag0l/secret-reach/actions/workflows/ci.yml/badge.svg)](https://github.com/garag0l/secret-reach/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Offline mode: zero dependencies](https://img.shields.io/badge/offline%20mode-0%20dependencies-brightgreen)

## Why this exists

Revoking the stolen credential is not enough. What limits the damage is rotating every secret the principal could
already have read. Wiz's response guidance for the Qubole cross-account access incident puts it this way: *"Rotate every
secret, SSM parameter, and Lambda environment variable the affected role could read. Revoking the role's active
sessions is also needed."*
([Wiz](https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild)). Other credential-theft cases follow the
same harvesting pattern (`ListSecrets` → `GetSecretValue`, `DescribeParameters` → `GetParameter`, `ListFunctions` →
environment variables):
[AntiFox](https://aviatrix.ai/threat-research-center/antifox-ai-pentesting-platform-aws-cloud-credential-theft-2026/),
[canary-credential research](https://mallory.ai/stories/01a1f422-5c2a-74b7-b9db-a91f30188789).

Responders usually build that list by hand. They enumerate resources in every region, then work through identity
policies, resource policies, KMS key policies and permission boundaries. secret-reach automates those steps. It
enumerates secret-bearing resources, decides for each one whether the principal can read it, and prints a rotation
checklist grouped by owner.

| Resource | Reported when | Readable via | Action |
|---|---|---|---|
| Secrets Manager secret | always | `secretsmanager:GetSecretValue` + resource policy + KMS key policy | rotate secret |
| SSM parameter | `SecureString`, or `String` with a secret-looking name | `ssm:GetParameter(s)`, `GetParameterHistory`, `GetParametersByPath` on a parent path + KMS | rotate value (and re-create `String` as `SecureString`) |
| Lambda function | has environment variables (names listed, never values) | `lambda:GetFunctionConfiguration`, `GetFunction`, or `ListFunctions` + function policy + KMS | rotate Lambda env values |
| ECS task definition | latest ACTIVE revision has plaintext env, env files, or `secrets` references | `ecs:DescribeTaskDefinition` | rotate plaintext values, move them to secrets |
| CodeBuild project | has environment variables | `codebuild:BatchGetProjects` | rotate `PLAINTEXT` values, move them to secrets |
| S3 bucket | name matches `tfstate`, `terraform`, `backup`, `dump`, `secrets`, ... | `s3:GetObject` + bucket policy + KMS (SSE-KMS) | review state/backups, rotate what's in them |
| EC2 instance | not terminated (user data is flagged, never read) | `ec2:DescribeInstanceAttribute` | review user data |

## Install

```bash
pipx install "git+https://github.com/garag0l/secret-reach"   # offline mode, zero dependencies
pipx inject secret-reach boto3                               # + live mode and `snapshot`
```

## Usage

```bash
# Live, read-only: collect from all enabled regions and evaluate the principal
secret-reach --principal arn:aws:iam::111122223333:role/integrations/vendor-x-integration --live --profile ir-readonly

# Session ARNs from CloudTrail work too; limit regions
secret-reach --principal arn:aws:sts::111122223333:assumed-role/vendor-x-integration/session --live --regions us-east-1,eu-west-1

# Snapshot once, evaluate offline as often as needed (no credentials needed for the evaluation)
secret-reach snapshot -o inventory.json --profile ir-readonly
secret-reach --principal arn:aws:iam::111122223333:role/integrations/vendor-x-integration --inventory inventory.json

# What would it call? (no credentials needed)
secret-reach --dry-run --regions us-east-1

# JSON/CSV for tickets and spreadsheets; SCPs; simulator cross-check; CloudTrail query
secret-reach --principal ARN --inventory inventory.json -f csv -o rotate.csv
secret-reach --principal ARN --inventory inventory.json --scp-export scps.json
secret-reach --principal ARN --live --simulate
secret-reach --principal ARN --inventory inventory.json --since 2026-11-01 --query-dialect athena --query-source cloudtrail_logs
```

Sample output for the demo inventory in [`examples/demo-inventory.json`](examples/demo-inventory.json). The demo is
built so that each policy interaction shows up once:

```text
$ secret-reach --principal arn:aws:sts::111122223333:assumed-role/vendor-x-integration/vendor-session \
    --inventory examples/demo-inventory.json --all
secret-reach 0.1.0  principal arn:aws:sts::111122223333:assumed-role/vendor-x-integration/vendor-session
source: examples/demo-inventory.json  account 111122223333  regions eu-west-1,us-east-1

owner: api
  STATUS        TYPE                   REGION          NAME                           ACTION
  readable      ecs-task-definition    eu-west-1       api-service                    rotate plaintext env values, then move them to secrets (re-encrypt) [app/DATABASE_URL, app/SENTRY_DSN, app/JWT_SIGNING_KEY (ref)]

owner: data
  STATUS        TYPE                   REGION          NAME                           ACTION
  not-readable  s3-bucket              us-east-1       acme-db-backups                review objects (state/backups); rotate credentials found in them
  not-readable  secretsmanager-secret  us-east-1       prod/db/master                 rotate secret

owner: partnerships
  STATUS        TYPE                   REGION          NAME                           ACTION
  conditional   secretsmanager-secret  eu-west-1       partner/acme-sftp              rotate secret

owner: payments
  STATUS        TYPE                   REGION          NAME                           ACTION
  readable      lambda-env             us-east-1       billing-webhook                rotate Lambda env values [DB_URL, STRIPE_SECRET, LOG_LEVEL]
  readable      secretsmanager-secret  us-east-1       prod/payments/stripe-api-key   rotate secret
  readable      ssm-parameter          us-east-1       /app/prod/db-password          rotate parameter value [SecureString]

owner: platform
  STATUS        TYPE                   REGION          NAME                           ACTION
  readable      ec2-user-data          us-east-1       i-0123456789abcdef0 (bastion)  review user data; rotate any credentials in it
  readable      s3-bucket              us-east-1       acme-terraform-state           review objects (state/backups); rotate credentials found in them
  readable      ssm-parameter          us-east-1       /app/prod/slack-webhook-url    rotate value; re-create as SecureString (re-encrypt) [String]
  not-readable  codebuild-env          us-east-1       deploy-prod                    rotate plaintext env values, then move them to secrets (re-encrypt) [NPM_TOKEN]
  not-readable  secretsmanager-secret  us-east-1       prod/root-credentials          rotate secret
  not-readable  ssm-parameter          us-east-1       /infra/vpn-psk                 rotate parameter value [SecureString]

Why conditional / not readable
  s3-bucket acme-db-backups: CMK arn:aws:kms:us-east-1:111122223333:key/9999aaaa-8888-bbbb-7777-cccc66665555: key policy denies kms:Decrypt
  secretsmanager-secret prod/db/master: CMK arn:aws:kms:us-east-1:111122223333:key/1111aaaa-2222-bbbb-3333-cccc4444dddd: key policy does not allow kms:Decrypt for this principal
  secretsmanager-secret partner/acme-sftp: kms:Decrypt is allowed only under a Condition (key policy/EnableIAM (account) + identity:vendor-x-read/DecryptViaServices); not evaluated
  codebuild-env deploy-prod: permission boundary does not allow codebuild:BatchGetProjects
  secretsmanager-secret prod/root-credentials: identity policy vendor-x-read/NeverRootCreds denies secretsmanager:GetSecretValue
  ssm-parameter /infra/vpn-psk: no policy allows ssm:GetParameter / ssm:GetParameters / ssm:GetParameterHistory / ssm:GetParametersByPath

7 readable, 1 conditional, 5 not readable
```

Here the role has `secretsmanager:GetSecretValue` on `*`. `prod/db/master` is still not readable, because its
customer-managed KMS key only trusts `db-admin`. The backup bucket's policy grants the vendor `s3:GetObject`, but its
key policy denies decryption. Without `--all`, only the readable and conditional rows are printed.

`--since DATE` adds a query that shows which of the reachable resources the principal *actually* read. It is
CloudTrail Lake SQL by default, or Athena SQL with `--query-dialect athena`. Excerpt:

```sql
SELECT eventTime, eventSource, eventName, awsRegion, sourceIPAddress, userIdentity.arn AS caller, errorCode, COALESCE(...) AS resource
FROM <event-data-store-id>
WHERE eventTime >= '2026-11-01 00:00:00'
  AND (userIdentity.arn = 'arn:aws:iam::111122223333:role/integrations/vendor-x-integration' OR userIdentity.sessionContext.sessionIssuer.arn = '...')
  AND (
       (eventSource = 'secretsmanager.amazonaws.com' AND eventName = 'GetSecretValue' AND element_at(requestParameters, 'secretId') IN ('partner/acme-sftp', 'prod/payments/stripe-api-key', ...))
    OR (eventSource = 'ssm.amazonaws.com' AND eventName = 'GetParameter' AND element_at(requestParameters, 'name') IN ('/app/prod/db-password', ...))
    OR (eventSource = 'lambda.amazonaws.com' AND eventName = 'GetFunctionConfiguration20150331v2' AND ...)
    ...
  )
ORDER BY eventTime;
```

`--format json` returns the same results with `granted_by` (which statement allowed each step), `reasons`, `checked`
actions and, with `--simulate`, the simulator's decision. `--format csv` writes one row per resource.

### Options worth knowing

- `--gaad FILE`: when the principal lives in another account (a vendor role, for example), pass that account's
  `aws iam get-account-authorization-details` output. Without it, the principal's identity policies are unknown. They
  are then assumed to allow everything, so reachable resources are reported as `conditional`, and only resource and
  key policies that trust the principal or its account can make something readable.
- `--scp-export FILE`: SCPs that apply to the principal's account. Accepted formats: one policy document, a list of
  documents, or `{"Policies": [{"Name": ..., "Content": ...}]}`. All SCPs are evaluated as one flattened set: any
  Deny blocks, and if the set contains Allow statements, one of them must match.
- `--simulate` (live only): calls `iam:SimulatePrincipalPolicy` for each resource and compares the result with the
  local identity-side decision. The simulator sees neither KMS key policies nor resource policies here.
  Disagreements are printed, but the result is not changed.
- `--owner-tag owner,team`: the tag keys to group by.

## Required permissions (live mode and `snapshot`)

All calls are read-only. `--dry-run` prints the exact list.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity", "iam:GetAccountAuthorizationDetails", "ec2:DescribeRegions",
      "secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy",
      "ssm:DescribeParameters", "ssm:ListTagsForResource",
      "lambda:ListFunctions", "lambda:GetPolicy", "lambda:ListTags",
      "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
      "codebuild:ListProjects", "codebuild:BatchGetProjects",
      "ec2:DescribeInstances",
      "kms:ListAliases", "kms:DescribeKey", "kms:GetKeyPolicy",
      "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetEncryptionConfiguration", "s3:GetBucketTagging"
    ],
    "Resource": "*"
  }]
}
```

Add `iam:SimulatePrincipalPolicy` for `--simulate`. A missing permission doesn't stop the run. The failed service or
region is listed under `collection error:` and the rest of the inventory is still evaluated.

**Be aware:** `lambda:ListFunctions`, `ecs:DescribeTaskDefinition` and `codebuild:BatchGetProjects` return
environment variable *values* in their responses. That is how AWS designed those APIs, and it is also why secret-reach
counts them as read paths. secret-reach keeps only the variable names and discards the values immediately. The role
you run it with can still see those values, so treat that role as sensitive.

## How "never reads a secret value" is enforced

- No `GetSecretValue`/`BatchGetSecretValue`, no `GetParameter(s)`/`GetParametersByPath`/`GetParameterHistory` (with or
  without `WithDecryption`), no `GetFunction*`, no `DescribeInstanceAttribute` (user data), no `GetObject`, no
  `kms:Decrypt`.
- `tests/test_no_secret_values.py` walks the AST of every module and fails on any of those calls, any `WithDecryption`
  keyword, dynamic `getattr` lookups of them, or any access to `value`/`Value` fields or `.values()`/`.items()` in the
  collector. It also checks that it catches a planted call.
- `tests/test_live.py` seeds fake values carrying a marker into moto (secrets, parameters, Lambda/ECS/CodeBuild env,
  an S3 object, EC2 user data). The test asserts that the marker appears in none of the snapshot, text, JSON, CSV or SQL
  output. It also records every API call botocore makes and checks it against the documented list.
- Loading an inventory that carries a `Value`/`SecretString`/`UserData` field is refused.

## How readability is decided

The tool runs a local evaluator over the snapshot (a simplified form of AWS policy evaluation logic):

- Any matching explicit `Deny` wins: SCP, identity policy, permission boundary, resource policy or key policy.
- **Same account:** the identity policy (within the permission boundary) allows the action, or the resource policy
  names the principal directly. A resource-policy grant to a role ARN is still limited by the boundary. A grant that
  names the account (`:root`) is not enough on its own.
- **Cross account:** the identity policy must allow the action and the resource policy must name the principal or its account.
- **KMS:** for customer-managed keys, the key policy is always required. Either it names the principal, or it names
  the account and the identity policy allows `kms:Decrypt`. AWS managed keys (`aws/secretsmanager`, `aws/ssm`,
  `aws/lambda`, ...) work for anyone in the same account and never cross account.
- Supported policy elements: `Action`/`NotAction`, `Resource`/`NotResource`, `Principal`/`NotPrincipal`, `*`/`?`
  wildcards.

## Limitations

- **Conditions are not evaluated.** An Allow that depends on a Condition makes the result `conditional`, and so
  does a Deny with a Condition. For incident response, treat `conditional` as readable until you've checked it.
- Not modelled: session policies, KMS grants, S3 ACLs and access points, resource control policies (RCPs), VPC
  endpoint policies, Lambda layers/versions. SCPs are evaluated only from `--scp-export`, as one flattened set
  without the OU hierarchy, and are assumed to apply to the principal.
- S3 access is judged on `bucket/*`. Access to only some prefixes is reported as `conditional`. Only buckets
  whose names match the pattern are inspected. Object contents are never listed or read.
- ECS: only the latest ACTIVE revision of each family is inspected. Older revisions may hold values that were
  later moved to secrets. EC2: every running or stopped instance is flagged, because checking whether user data
  contains a credential would mean reading it. Launch templates aren't covered yet.
- Not yet covered: App Runner, Elastic Beanstalk, Glue connections, CloudFormation parameters.
- Cross-account principals need `--gaad` from their own account for an exact answer. Without it, the result is the
  worst case.
- The `--simulate` cross-check compares identity-side decisions only.
- The `--since` query matches single-resource reads by name or ARN. Batch and list calls (`GetParameters`,
  `BatchGetSecretValue`, `ListFunctions`, `BatchGetProjects`) are listed without a resource filter. S3 `GetObject` only
  appears if S3 data events were enabled.
- The tool hasn't been benchmarked against the issue's target of 17 regions × 500 resources in under 2 minutes.
  Regions are collected in parallel (`--workers`, default 8) with adaptive retry and backoff.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

## Authorized use only

Use secret-reach only on AWS accounts you own or are explicitly authorized to assess. It is a defensive,
read-only tool for incident response and least-privilege reviews. It reports which resources a principal can
reach and never retrieves their contents.

## License

[MIT](LICENSE)
