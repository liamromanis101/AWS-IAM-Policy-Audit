#!/usr/bin/env python3
"""
AWS IAM Permissiveness Audit — refactor of aws-iam-allactions.py

Goals
-----
- Keep the original wildcard/many-actions checks.
- Add attachment awareness (which users/roles/groups are affected).
- Optional effective-access simulation per principal (curated sensitive actions).
- Optional privilege-escalation pattern detection.
- Optional cross-account trust & exposure checks for roles.
- Track and print findings for any **insufficient permissions** encountered (e.g., AccessDenied).
- Scoring model (impact × likelihood × exposure) and multi-format output.

Usage (examples)
----------------
python aws-iam-permissiveness-audit.py --simulate --check-privesc --check-cross-account \
  --format json --output findings.json --profile myprof --region us-east-1

python aws-iam-permissiveness-audit.py --threshold 30 --include-aws-managed --format table
"""

import argparse
import concurrent.futures as futures
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except Exception as e:  # pragma: no cover
    print("boto3 is required: pip install boto3", file=sys.stderr)
    raise

# ------------------------- config & constants -------------------------
DEFAULT_THRESHOLD = 20
DEFAULT_SENSITIVE_SERVICES = [
    "iam", "sts", "s3", "kms", "ec2", "lambda", "ecr", "secretsmanager", "ssm", "organizations",
]
# A small curated set of sensitive, high-impact actions for simulation. Add more as needed.
SENSITIVE_ACTIONS_SEED = sorted({
    # IAM and identity
    "iam:PassRole", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy",
    # STS
    "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
    # Data plane (examples)
    "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:PutBucketPolicy", "s3:GetBucketAcl",
    # Compute / execution
    "lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction",
    "ec2:RunInstances", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
    "ecs:RunTask",
    # Secrets / keys
    "kms:Decrypt", "kms:Encrypt", "kms:CreateGrant", "secretsmanager:GetSecretValue",
})

PRIVESC_RULES = [
    {"name": "PassRole+Compute", "actions": ["iam:PassRole", "lambda:CreateFunction", "ecs:RunTask", "ec2:RunInstances"]},
    {"name": "PolicyAttachment", "actions": ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy"]},
    {"name": "TrustPolicyEdit", "actions": ["iam:UpdateAssumeRolePolicy"]},
    {"name": "CredsCreation", "actions": ["iam:CreateAccessKey", "iam:CreateLoginProfile"]},
]

# ------------------------- helper utilities -------------------------
def ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def flatten_actions(actions: Any) -> List[str]:
    """Return list of actions as lower-case strings (handles str or list)."""
    out: List[str] = []
    for a in ensure_list(actions):
        if not a:
            continue
        out.append(str(a).strip())
    return [s for s in map(str.lower, out) if s]


def normalize_statement(stmt: Dict[str, Any]) -> Tuple[List[str], List[str], List[str], str, Dict[str, Any]]:
    actions = flatten_actions(stmt.get("Action"))
    not_actions = flatten_actions(stmt.get("NotAction"))
    resources = [r if isinstance(r, str) else json.dumps(r) for r in ensure_list(stmt.get("Resource") or ["*"])]
    effect = (stmt.get("Effect") or "Allow").title()
    cond = stmt.get("Condition") or {}
    return actions, not_actions, resources, effect, cond


def is_unrestricted(actions: List[str], resources: List[str], effect: str, cond: Dict[str, Any]) -> bool:
    if effect != "Allow":
        return False
    # Action wildcard (service:* or *) AND fully unscoped resources AND no conditions
    action_wild = any(a == "*" or a.endswith(":*") for a in actions)
    resource_wild = any(r == "*" or ":*" in r for r in resources)
    return action_wild and resource_wild and not cond


def count_unique_actions(actions: List[str]) -> int:
    return len(set(actions))


def score_finding(impact: float, likelihood: float, exposure: float) -> float:
    impact = max(0.0, min(10.0, impact))
    likelihood = max(0.0, min(10.0, likelihood))
    exposure = max(0.0, min(10.0, exposure))
    # 0..100 scale
    return round((impact * likelihood * exposure), 1)

# ------------------------- data models -------------------------
@dataclass
class Attachment:
    type: str  # User | Role | Group
    name: str
    arn: str


@dataclass
class Finding:
    account_id: str
    policy_arn: str
    policy_name: str
    attachment_type: str  # managed | inline | n/a
    principal_type: Optional[str] = None
    principal_name: Optional[str] = None
    principal_arn: Optional[str] = None
    risk_type: str = ""
    detail: str = ""
    action_count: Optional[int] = None
    conditions: Optional[Dict[str, Any]] = None
    explicit_denies: int = 0
    exposure: str = "internal"  # internal | external-account | public
    allowed_examples: Optional[List[str]] = None
    privesc_hits: Optional[List[str]] = None
    severity_score: Optional[float] = None

# ------------------------- boto session helpers -------------------------
def make_session(profile: Optional[str], region: Optional[str]):
    if profile:
        boto3.setup_default_session(profile_name=profile)
    return boto3.session.Session(region_name=region)


def assume_role_if_needed(session, role_arn: Optional[str]):
    if not role_arn:
        return session
    sts = session.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="iam-permissiveness-audit")
    c = creds["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=session.region_name,
    )

# ------------------------- IAM enumeration -------------------------
def list_policies(iam, include_aws_managed: bool) -> Iterable[Dict[str, Any]]:
    scopes = ["Local"] + (["AWS"] if include_aws_managed else [])
    for scope in scopes:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope=scope):
            for p in page.get("Policies", []):
                yield p


def list_entities_for_policy(iam, policy_arn: str) -> Dict[str, List[Attachment]]:
    out: Dict[str, List[Attachment]] = {"User": [], "Role": [], "Group": []}
    paginator = iam.get_paginator("list_entities_for_policy")
    for page in paginator.paginate(PolicyArn=policy_arn):
        for u in page.get("PolicyUsers", []):
            out["User"].append(Attachment("User", u["UserName"], u["UserArn"]))
        for r in page.get("PolicyRoles", []):
            out["Role"].append(Attachment("Role", r["RoleName"], r["RoleArn"]))
        for g in page.get("PolicyGroups", []):
            out["Group"].append(Attachment("Group", g["GroupName"], g["GroupArn"]))
    return out


def get_role_trust(iam, role_name: str) -> Dict[str, Any]:
    role = iam.get_role(RoleName=role_name)["Role"]
    return role.get("AssumeRolePolicyDocument", {})

# ------------------------- simulation & analysis -------------------------
def simulate_principal_actions(iam, arn: str, actions: List[str], resources: Optional[List[str]] = None) -> List[str]:
    """Return list of actions from `actions` that evaluate as allowed for the given principal."""
    allowed: List[str] = []
    # Split in chunks of 100 (API limit)
    chunk = 100
    for i in range(0, len(actions), chunk):
        part = actions[i:i+chunk]
        resp = iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=part,
            ResourceArns=resources or ["*"],
        )
        for e in resp.get("EvaluationResults", []):
            if e.get("EvalDecision", "").lower() == "allowed":
                allowed.append(e.get("EvalActionName"))
    return allowed


def check_privesc(allowed_actions: Iterable[str]) -> List[str]:
    aset = {a.lower() for a in allowed_actions}
    hits: List[str] = []
    for rule in PRIVESC_RULES:
        if all(a.lower() in aset for a in rule["actions"]):
            hits.append(rule["name"])
    return hits

# ------------------------- core audit -------------------------
def audit_policy_document(policy_doc: Dict[str, Any], threshold: int) -> Dict[str, Any]:
    """Return quick risk summary for a single policy document (no attachments)."""
    stmts = ensure_list(policy_doc.get("Statement") or [])
    wildcard_hits: List[Dict[str, Any]] = []
    many_action_hits: List[Dict[str, Any]] = []

    for stmt in stmts:
        actions, not_actions, resources, effect, cond = normalize_statement(stmt)
        explicit_denies = 1 if effect == "Deny" else 0
        if is_unrestricted(actions, resources, effect, cond):
            wildcard_hits.append({
                "statement": stmt,
                "conditions": cond,
                "explicit_denies": explicit_denies,
            })
            continue
        # Skip NotAction blocks for many-actions heuristic; they need a different analysis.
        if actions and effect == "Allow":
            cnt = count_unique_actions(actions)
            if cnt >= threshold:
                many_action_hits.append({
                    "statement": stmt,
                    "count": cnt,
                    "conditions": cond,
                    "explicit_denies": explicit_denies,
                })

    return {"wildcard": wildcard_hits, "many_actions": many_action_hits}


def analyze_cross_account_exposure(trust_doc: Dict[str, Any], self_acct: str) -> str:
    """Rough classifier for role trust policies: public / external-account / internal."""
    principals: List[str] = []
    for stmt in ensure_list(trust_doc.get("Statement") or []):
        principal = stmt.get("Principal")
        if isinstance(principal, dict):
            for v in principal.values():
                principals += ensure_list(v)
        elif isinstance(principal, str):
            principals.append(principal)
    principals = [str(p) for p in principals]
    if any(p == "*" for p in principals):
        return "public"
    acct_ids: Set[str] = set()
    for p in principals:
        if p.startswith("arn:aws:iam::"):
            try:
                acct_ids.add(p.split("::")[1].split(":")[0])
            except Exception:
                pass
    # If any account differs from self, call it external-account
    if any(a != self_acct for a in acct_ids):
        return "external-account"
    return "internal"


def severity_from_factors(is_wildcard: bool, action_count: int, exposure: str, has_conditions: bool) -> float:
    impact = 9.5 if is_wildcard else min(9.0, 4 + action_count / 10)
    exposure_map = {"public": 10, "external-account": 8, "internal": 5}
    exposure_score = exposure_map.get(exposure, 5)
    likelihood = 6.0
    if has_conditions:
        likelihood -= 2.0
    return score_finding(impact, likelihood, exposure_score)

def make_insufficient_perm_finding(account_id: str, policy_arn: str, policy_name: str, operation: str, err: Exception) -> Finding:
    code = None
    msg = None
    try:
        code = err.response.get("Error", {}).get("Code")       # type: ignore[attr-defined]
        msg  = err.response.get("Error", {}).get("Message")    # type: ignore[attr-defined]
    except Exception:
        pass
    detail = f"{operation} failed: {code or type(err).__name__}: {msg or str(err)}"
    return Finding(
        account_id=account_id,
        policy_arn=policy_arn,
        policy_name=policy_name,
        attachment_type="managed",
        risk_type="insufficient-permissions",
        detail=detail,
        severity_score=0.0,
    )

def run_audit(
    profile: Optional[str], region: Optional[str], assume_role_arn: Optional[str], threshold: int,
    include_aws_managed: bool, simulate: bool, check_privesc_flag: bool, check_cross_acct: bool,
    services: List[str], max_workers: int
) -> List[Finding]:
    base_session = make_session(profile, region)
    session = assume_role_if_needed(base_session, assume_role_arn)
    cfg = BotoConfig(retries={"max_attempts": 10, "mode": "standard"})
    iam = session.client("iam", config=cfg)

    # Resolve account id
    account_id = session.client("sts").get_caller_identity().get("Account")

    sensitive_actions = [a for a in SENSITIVE_ACTIONS_SEED if a.split(":")[0] in services or a == "*"]

    findings: List[Finding] = []
    errors: List[str] = []  # kept for debugging; not shown unless converted to findings

    # Enumerate policies and analyze
    policy_iter = list_policies(iam, include_aws_managed)

    def process_policy(p: Dict[str, Any]) -> List[Finding]:
        res: List[Finding] = []
        policy_arn = p["Arn"]
        policy_name = p["PolicyName"]

        # Fetch default policy version with per-operation error capture
        try:
            pol = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        except ClientError as e:
            errors.append(f"iam:GetPolicy failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetPolicy", e))
            return res

        try:
            ver = iam.get_policy_version(PolicyArn=policy_arn, VersionId=pol["DefaultVersionId"])  # type: ignore
            policy_doc = ver["PolicyVersion"]["Document"]
            quick = audit_policy_document(policy_doc, threshold)
        except ClientError as e:
            errors.append(f"iam:GetPolicyVersion failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetPolicyVersion", e))
            return res

        # Attachments
        try:
            attached = list_entities_for_policy(iam, policy_arn)
        except ClientError as e:
            errors.append(f"iam:ListEntitiesForPolicy failed for {policy_arn}: {e}")
            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:ListEntitiesForPolicy", e))
            attached = {"User": [], "Role": [], "Group": []}

        # Turn policy-centric hits into principal-centric findings
        def mk_find(principal: Optional[Attachment], risk_type: str, detail: str, action_count: Optional[int], conditions: Optional[Dict[str, Any]], exposure: str, explicit_denies: int) -> Finding:
            return Finding(
                account_id=account_id,
                policy_arn=policy_arn,
                policy_name=policy_name,
                attachment_type="managed",
                principal_type=(principal.type if principal else None),
                principal_name=(principal.name if principal else None),
                principal_arn=(principal.arn if principal else None),
                risk_type=risk_type,
                detail=detail,
                action_count=action_count,
                conditions=conditions,
                explicit_denies=explicit_denies,
                exposure=exposure,
            )

        # Wildcards
        for hit in quick["wildcard"]:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            if not principals:
                principals = [None]  # unattached policy still worth reporting
            for principal in principals:
                exposure = "internal"
                if check_cross_acct and principal and principal.type == "Role":
                    try:
                        trust = get_role_trust(iam, principal.name)
                        exposure = analyze_cross_account_exposure(trust, account_id)
                    except ClientError as e:
                        errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                        res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                f = mk_find(
                    principal,
                    "wildcard",
                    "Effect:Allow with Action:* (or service:*) and Resource:* with no conditions",
                    None,
                    hit.get("conditions"),
                    exposure,
                    hit.get("explicit_denies", 0),
                )
                has_conditions = bool(f.conditions)
                f.severity_score = severity_from_factors(True, 999, f.exposure, has_conditions)
                res.append(f)

        # Many-actions
        for hit in quick["many_actions"]:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            if not principals:
                principals = [None]
            for principal in principals:
                exposure = "internal"
                if check_cross_acct and principal and principal.type == "Role":
                    try:
                        trust = get_role_trust(iam, principal.name)
                        exposure = analyze_cross_account_exposure(trust, account_id)
                    except ClientError as e:
                        errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                        res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                f = mk_find(
                    principal,
                    "many-actions",
                    "Effect:Allow with many distinct actions (≥ threshold)",
                    hit.get("count"),
                    hit.get("conditions"),
                    exposure,
                    hit.get("explicit_denies", 0),
                )
                has_conditions = bool(f.conditions)
                f.severity_score = severity_from_factors(False, f.action_count or 0, f.exposure, has_conditions)
                res.append(f)

        # Optional simulation & privesc per principal
        if simulate or check_privesc_flag:
            principals = attached["User"] + attached["Role"] + attached["Group"]
            for principal in principals:
                try:
                    allowed = simulate_principal_actions(iam, principal.arn, sensitive_actions)
                except ClientError as e:
                    errors.append(f"SimulatePrincipalPolicy failed for {principal.arn}: {e}")
                    res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:SimulatePrincipalPolicy", e))
                    allowed = []
                if allowed:
                    f = mk_find(
                        principal,
                        "effective-access",
                        "Principal is allowed selected sensitive actions (simulation)",
                        len(allowed),
                        None,
                        "internal",
                        0,
                    )
                    if check_cross_acct and principal.type == "Role":
                        try:
                            trust = get_role_trust(iam, principal.name)
                            f.exposure = analyze_cross_account_exposure(trust, account_id)
                        except ClientError as e:
                            errors.append(f"iam:GetRole failed for {policy_arn}: {e}")
                            res.append(make_insufficient_perm_finding(account_id, policy_arn, policy_name, "iam:GetRole", e))
                    f.allowed_examples = sorted(allowed)[:25]
                    f.severity_score = severity_from_factors(False, len(allowed), f.exposure, False)
                    if check_privesc_flag:
                        f.privesc_hits = check_privesc(allowed)
                        if f.privesc_hits:
                            f.severity_score = min(100.0, (f.severity_score or 0) + 10.0)
                    res.append(f)

        return res

    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for chunk_findings in ex.map(process_policy, policy_iter, chunksize=5):
            findings.extend(chunk_findings)

    # (Optional) Surface unexpected errors as findings (commented out by default)
    # for err in errors:
    #     findings.append(Finding(
    #         account_id=account_id,
    #         policy_arn="",
    #         policy_name="",
    #         attachment_type="n/a",
    #         risk_type="internal-error",
    #         detail=err,
    #         severity_score=0.0,
    #     ))

    return findings

# ------------------------- output -------------------------
def to_table(findings: List[Finding]) -> str:
    # Summaries by risk type (including insufficient-permissions)
    totals = defaultdict(int)
    for f in findings:
        totals[f.risk_type] += 1

    headers = [
        "severity", "risk_type", "principal", "policy", "attachment", "exposure", "actions", "privesc", "detail",
    ]
    rows = []
    for f in sorted(findings, key=lambda x: (-(x.severity_score or 0), x.risk_type)):
        principal = f"{f.principal_type or '-'}:{f.principal_name or '-'}"
        policy = f"{f.policy_name or '-'}"
        rows.append([
            f.severity_score,
            f.risk_type,
            principal,
            policy,
            f.attachment_type,
            f.exposure,
            f.action_count or (len(f.allowed_examples or []) if f.allowed_examples else 0),
            ",".join(f.privesc_hits or []) if f.privesc_hits else "",
            (f.detail[:80] + "…") if len(f.detail) > 80 else f.detail,
        ])
    # Minimal fixed-width table to avoid extra deps
    colw = [max(len(str(c)) for c in [h] + [r[i] for r in rows]) for i, h in enumerate(headers)]
    line = "+" + "+".join("-" * (w + 2) for w in colw) + "+"
    out = []
    if totals:
        summary_items = ", ".join(f"{k}={v}" for k, v in sorted(totals.items()))
        out.append(f"Findings summary: {summary_items}")
    out.append(line)
    out.append("| " + " | ".join(str(h).ljust(colw[i]) for i, h in enumerate(headers)) + " |")
    out.append(line)
    for r in rows:
        out.append("| " + " | ".join(str(r[i]).ljust(colw[i]) for i in range(len(headers))) + " |")
    out.append(line)
    return "\n".join(out)


def to_json(findings: List[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, default=str)


def to_csv(findings: List[Finding]) -> str:
    # Return CSV as string
    headers = [
        "account_id","policy_arn","policy_name","attachment_type","principal_type","principal_name","principal_arn",
        "risk_type","detail","action_count","conditions","explicit_denies","exposure","allowed_examples","privesc_hits","severity_score"
    ]
    from io import StringIO
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for f in findings:
        w.writerow([
            f.account_id, f.policy_arn, f.policy_name, f.attachment_type, f.principal_type, f.principal_name, f.principal_arn,
            f.risk_type, f.detail, f.action_count, json.dumps(f.conditions or {}), f.explicit_denies, f.exposure,
            ";".join(f.allowed_examples or []) if f.allowed_examples else "", ";".join(f.privesc_hits or []) if f.privesc_hits else "",
            f.severity_score,
        ])
    return buf.getvalue()


def write_output(findings: List[Finding], fmt: str, output: Optional[str]):
    if fmt == "json":
        data = to_json(findings)
    elif fmt == "csv":
        data = to_csv(findings)
    elif fmt == "table":
        data = to_table(findings)
    else:
        raise SystemExit(f"Unsupported format: {fmt}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(data)
        print(f"Wrote {fmt.upper()} to {output}")
    else:
        print(data)

# ------------------------- CLI -------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit IAM policy permissiveness with attachments, simulation and scoring")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Action count threshold for many-actions")
    p.add_argument("--include-aws-managed", action="store_true", help="Include AWS-managed policies")
    p.add_argument("--simulate", action="store_true", help="Simulate sensitive actions per principal")
    p.add_argument("--check-privesc", action="store_true", help="Detect privilege escalation patterns (requires --simulate for best results)")
    p.add_argument("--check-cross-account", action="store_true", help="Analyze role trust policies for external/public exposure")
    p.add_argument("--services", default=",".join(DEFAULT_SENSITIVE_SERVICES), help="Comma-separated services to include in sensitive action simulation (e.g., s3,iam,kms)")
    p.add_argument("--format", choices=["json","csv","table"], default="table", help="Output format")
    p.add_argument("--output", help="Path to write output; prints to stdout if omitted")
    p.add_argument("--profile", help="AWS profile name")
    p.add_argument("--region", help="AWS region (for STS/clients)")
    p.add_argument("--assume-role-arn", help="Role ARN to assume before scanning")
    p.add_argument("--max-workers", type=int, default=8, help="Concurrency for policy processing")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    services = [s.strip().lower() for s in args.services.split(",") if s.strip()]

    findings = run_audit(
        profile=args.profile,
        region=args.region,
        assume_role_arn=args.assume_role_arn,
        threshold=args.threshold,
        include_aws_managed=args.include_aws_managed,
        simulate=args.simulate,
        check_privesc_flag=args.check_privesc,
        check_cross_acct=args.check_cross_account,
        services=services,
        max_workers=args.max_workers,
    )

    write_output(findings, args.format, args.output)
    print("Scan complete.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
