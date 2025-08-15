# AWS IAM Permissiveness Audit

A Python 3 tool to analyze AWS IAM policies for risky permissions, track affected principals, simulate sensitive actions, and record permission errors when the audit account cannot read a policy or attachment.

## Features

* **Wildcard detection** — Flags policies with `Action: "*"` or `service:*` and unrestricted resources.
* **Many-actions detection** — Flags policies with more than a configurable number of distinct allowed actions.
* **Attachment awareness** — Lists which users, roles, and groups are affected by each risky policy.
* **Sensitive action simulation** — Uses `iam:SimulatePrincipalPolicy` to test if principals can perform curated high-risk actions (e.g., `iam:PassRole`, `s3:*`, `kms:*`).
* **Privilege escalation detection** — Identifies common IAM privilege escalation patterns.
* **Cross-account trust analysis** — Flags roles that can be assumed by external accounts or the public.
* **Permission error tracking** — Records when the auditing identity lacks permissions to retrieve a policy or attachment, including the operation and error message.
* **Severity scoring** — Assigns a numeric severity score based on impact, exposure, and likelihood.
* **Multi-format output** — Table, JSON, or CSV with summaries by finding type.

## Installation

```bash
pip install boto3
```

## Usage

```bash
python aws-iam-permissiveness-audit.py [options]
```

### Options

| Option                      | Description                                                   |
| --------------------------- | ------------------------------------------------------------- |
| `--h`                       | Prints help message                                           |
| `--threshold N`             | Action count threshold for many-actions (default: 20)         |
| `--include-aws-managed`     | Include AWS-managed policies in the scan                      |
| `--simulate`                | Simulate sensitive actions per principal                      |
| `--check-privesc`           | Detect privilege escalation patterns (best with `--simulate`) |
| `--check-cross-account`     | Analyze role trust policies for external/public exposure      |
| `--services s1,s2,...`      | Services to include in sensitive action simulation            |
| `--format table\|json\|csv` | Output format (default: table)                                |
| `--output FILE`             | Write results to file instead of stdout                       |
| `--profile PROFILE`         | AWS CLI profile name to use                                   |
| `--region REGION`           | AWS region (for STS and service calls)                        |
| `--assume-role-arn ARN`     | Role ARN to assume before scanning                            |
| `--max-workers N`           | Concurrency for policy processing (default: 8)                |
|  --sensitive-actions-file FILE` | Path to JSON file (array of actions) to treat as sensitive |

## Example

Scan all customer-managed policies in the default AWS CLI profile, simulate sensitive actions, check for privilege escalation, and output JSON:

```bash
python aws-iam-permissiveness-audit.py --simulate --check-privesc --format json --output findings.json
```

## Severity Score Legend

* **80–100: Critical** — Wildcard permissions with public or external exposure, or confirmed privilege escalation.
* **50–79: High** — Broad permissions with many sensitive actions and high exposure, but not fully public.
* **20–49: Medium** — Wildcard or broad permissions internal-only, or mitigated by strong conditions.
* **1–19: Low** — Narrow permissions or restrictive conditions.
* **0: Informational** — No confirmed access or insufficient permissions to evaluate.

## Output

Findings include:

* **Risk type** (`wildcard`, `many-actions`, `effective-access`, `permission-error`, etc.)
* **Principal** affected (`User`, `Role`, or `Group`)
* **Policy** name and ARN
* **Exposure** (internal, external-account, public)
* **Allowed actions** (for simulation results)
* **Privilege escalation hits** (if any)
* **Severity score**

Permission errors are shown as `permission-error` findings with the failed operation and AWS error message.

## Example Output

### Example findings (GitHub Markdown)

Findings summary: wildcard=2, many-actions=1, insufficient-permissions=1

| severity | risk_type                | principal       | policy               | attachment | exposure         | actions | privesc | detail                                         |
|----------|--------------------------|-----------------|----------------------|------------|------------------|---------|---------|------------------------------------------------|
| 91.0     | wildcard                 | Role:AdminRole  | AdminAccess          | managed    | public           | 999     |         | Effect:Allow with Action:* and Resource:*     |
| 75.0     | many-actions             | User:JohnDoe    | CustomPowerUser      | managed    | external-account | 240     |         | Effect:Allow with many distinct actions       |
| 68.0     | privesc                  | Role:DevOpsRole   | EscalationPolicy     | managed    | external-account | 15      | PassRole, CreatePolicyVersion             | Policy allows IAM role creation and policy edits |
| 28.5     | wildcard                 | Role:DevOpsRole | DevOpsWildcardPolicy | managed    | internal         | 999     |         | Effect:Allow with Action:* and Resource:*     |
| 0.0      | insufficient-permissions | -:-             | SecretPolicy         | managed    | internal         | 0       |         | iam:GetPolicy failed: AccessDenied: Not allowed |

## Requirements

* Python 3.7+
* `boto3`
* IAM permissions to list and get policies, list attachments, simulate policies, and get roles.

## License

Apache 
