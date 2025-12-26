from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import datetime as dt
import csv
import io

import boto3
from botocore.exceptions import ClientError


@dataclass
class Finding:
    id: str
    title: str
    status: str  # PASS | WARN | FAIL
    details: str
    evidence: Dict[str, Any]


def _session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def _safe(callable_, *, default=None, on_error_prefix: str = ""):
    """
    Always returns a tuple: (result, error_message_or_None)
    """
    try:
        return callable_(), None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        return default, f"{on_error_prefix}{code}: {e}"
    except Exception as e:
        return default, f"{on_error_prefix}{type(e).__name__}: {e}"


def check_sts(session) -> Finding:
    sts = session.client("sts")
    resp, err = _safe(lambda: sts.get_caller_identity(), default=None, on_error_prefix="sts.get_caller_identity failed: ")
    if err:
        return Finding("sts_identity", "STS caller identity", "FAIL", err, {})
    return Finding(
        "sts_identity",
        "STS caller identity",
        "PASS",
        "Able to call sts:GetCallerIdentity with provided profile.",
        {"account": resp.get("Account"), "arn": resp.get("Arn"), "user_id": resp.get("UserId")},
    )


def check_guardduty(session) -> Finding:
    gd = session.client("guardduty")
    resp, err = _safe(lambda: gd.list_detectors(), default={"DetectorIds": []}, on_error_prefix="guardduty.list_detectors failed: ")
    if err:
        return Finding("guardduty", "GuardDuty enabled", "WARN", err, {})

    dets = resp.get("DetectorIds", [])
    if not dets:
        return Finding("guardduty", "GuardDuty enabled", "FAIL", "No GuardDuty detector found (not enabled).", {"detectors": []})

    # Check first detector status
    det_id = dets[0]
    det, err2 = _safe(lambda: gd.get_detector(DetectorId=det_id), default=None, on_error_prefix="guardduty.get_detector failed: ")
    if err2:
        return Finding("guardduty", "GuardDuty enabled", "WARN", err2, {"detector_id": det_id})

    status = "PASS" if det.get("Status") == "ENABLED" else "FAIL"
    return Finding(
        "guardduty",
        "GuardDuty enabled",
        status,
        f"GuardDuty detector status: {det.get('Status')}",
        {"detector_id": det_id, "status": det.get("Status")},
    )


def check_cloudtrail(session, expected_trail_name: str = "baseline-cloudtrail") -> Finding:
    ct = session.client("cloudtrail")
    trails, err = _safe(lambda: ct.describe_trails(trailNameList=[expected_trail_name], includeShadowTrails=False), default=None,
                        on_error_prefix="cloudtrail.describe_trails failed: ")
    if err:
        return Finding("cloudtrail", "CloudTrail exists and logging", "WARN", err, {})

    tlist = (trails or {}).get("trailList", [])
    if not tlist:
        return Finding("cloudtrail", "CloudTrail exists and logging", "FAIL", f"Trail not found: {expected_trail_name}", {"trail_name": expected_trail_name})

    status_resp, err2 = _safe(lambda: ct.get_trail_status(Name=expected_trail_name), default=None, on_error_prefix="cloudtrail.get_trail_status failed: ")
    if err2:
        return Finding("cloudtrail", "CloudTrail exists and logging", "WARN", err2, {"trail_name": expected_trail_name})

    is_logging = bool(status_resp.get("IsLogging"))
    if is_logging:
        return Finding(
            "cloudtrail",
            "CloudTrail exists and logging",
            "PASS",
            "CloudTrail exists and IsLogging=true.",
            {"trail_name": expected_trail_name, "status": status_resp},
        )
    return Finding(
        "cloudtrail",
        "CloudTrail exists and logging",
        "FAIL",
        "CloudTrail exists but is not logging.",
        {"trail_name": expected_trail_name, "status": status_resp},
    )


def check_log_group(session, name: str = "/aws/cloudtrail/baseline", min_retention_days: int = 30) -> Finding:
    logs = session.client("logs")
    resp, err = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name), default={"logGroups": []},
                      on_error_prefix="logs.describe_log_groups failed: ")
    if err:
        return Finding("log_group", "CloudWatch Log Group retention", "WARN", err, {})

    groups = resp.get("logGroups", [])
    group = next((g for g in groups if g.get("logGroupName") == name), None)
    if not group:
        return Finding("log_group", "CloudWatch Log Group retention", "FAIL", f"Log group not found: {name}", {"searched_prefix": name})

    retention = group.get("retentionInDays")
    if retention is None:
        return Finding("log_group", "CloudWatch Log Group retention", "WARN", "Log group has NO retention set (keeps forever).", {"log_group": name})
    if retention >= min_retention_days:
        return Finding("log_group", "CloudWatch Log Group retention", "PASS", f"Retention is {retention} days.", {"log_group": name, "retention_days": retention})
    return Finding("log_group", "CloudWatch Log Group retention", "WARN", f"Retention is {retention} days (< {min_retention_days}).", {"log_group": name, "retention_days": retention})


def check_sns_topic(session, name: str = "baseline-alerts") -> Finding:
    sns = session.client("sns")
    resp, err = _safe(lambda: sns.list_topics(), default={"Topics": []}, on_error_prefix="sns.list_topics failed: ")
    if err:
        return Finding("sns_topic", "SNS alerts topic exists", "WARN", err, {})

    topics = [t.get("TopicArn", "") for t in resp.get("Topics", [])]
    arn = next((a for a in topics if a.endswith(f":{name}")), None)
    if not arn:
        return Finding("sns_topic", "SNS alerts topic exists", "FAIL", f"SNS topic not found: {name}", {"topics_seen": topics[:20]})
    return Finding("sns_topic", "SNS alerts topic exists", "PASS", f"Found SNS topic: {arn}", {"topic_arn": arn})


def check_cloudwatch_alarms(session, names: List[str]) -> Finding:
    cw = session.client("cloudwatch")
    resp, err = _safe(
        lambda: cw.describe_alarms(AlarmNames=names),
        default={"MetricAlarms": []},
        on_error_prefix="cloudwatch.describe_alarms failed: ",
    )
    if err:
        return Finding("alarms", "CloudWatch alarms status", "WARN", err, {})

    found = {a.get("AlarmName"): a for a in resp.get("MetricAlarms", [])}
    missing = [n for n in names if n not in found]
    if missing:
        return Finding(
            "alarms",
            "CloudWatch alarms status",
            "FAIL",
            f"Missing alarms: {', '.join(missing)}",
            {"missing": missing, "found": list(found.keys())},
        )

    # Evaluate states
    alarm_states = {
        name: {
            "state": a.get("StateValue"),
            "reason": a.get("StateReason"),
            "updated": a.get("StateUpdatedTimestamp"),
        }
        for name, a in found.items()
    }

    # Decide overall status:
    # If any ALARM => FAIL, if any INSUFFICIENT_DATA => WARN, else PASS
    states = [a.get("StateValue") for a in found.values()]
    if any(s == "ALARM" for s in states):
        status = "FAIL"
        details = "One or more alarms are in ALARM state."
    elif any(s == "INSUFFICIENT_DATA" for s in states):
        status = "WARN"
        details = "One or more alarms are in INSUFFICIENT_DATA state."
    else:
        status = "PASS"
        details = "All expected alarms exist and are OK."

    return Finding(
        "alarms",
        "CloudWatch alarms status",
        status,
        details,
        {"alarms": alarm_states},
    )


def _csv_text_from_credential_report(iam_client) -> str:
    # Content ist base64-encoded CSV
    content_b64 = iam_client.get_credential_report()["Content"]
    text = content_b64.decode("utf-8", errors="replace")
    return text.lstrip("\ufeff")  # BOM weg


def check_iam_mfa(session) -> Finding:
    iam = session.client("iam")

    # Alle IAM User holen
    users_resp, err = _safe(lambda: iam.list_users(), default={"Users": []}, on_error_prefix="iam.list_users failed: ")
    if err:
        return Finding("iam_mfa", "MFA for IAM users", "WARN", err, {})

    users_without = []

    for u in users_resp.get("Users", []):
        username = u["UserName"]

        # Nur User checken, die Console Password haben
        login_profile, lp_err = _safe(
            lambda: iam.get_login_profile(UserName=username),
            default=None,
            on_error_prefix=f"iam.get_login_profile({username}) failed: ",
        )

        # Wenn kein LoginProfile -> User hat kein Console Passwort -> skip
        # get_login_profile wirft NoSuchEntity, das fangen wir über _safe als err ab
        if lp_err and "NoSuchEntity" in lp_err:
            continue
        if lp_err and "NoSuchEntity" not in lp_err:
            return Finding("iam_mfa", "MFA for IAM users", "WARN", lp_err, {"user": username})

        # MFA Devices prüfen (live)
        mfa_resp, mfa_err = _safe(
            lambda: iam.list_mfa_devices(UserName=username),
            default={"MFADevices": []},
            on_error_prefix=f"iam.list_mfa_devices({username}) failed: ",
        )
        if mfa_err:
            return Finding("iam_mfa", "MFA for IAM users", "WARN", mfa_err, {"user": username})

        if len(mfa_resp.get("MFADevices", [])) == 0:
            users_without.append(username)

    if users_without:
        return Finding(
            "iam_mfa",
            "MFA for IAM users",
            "WARN",
            f"{len(users_without)} IAM user(s) with console password but without MFA.",
            {"users_without_mfa": users_without},
        )

    return Finding("iam_mfa", "MFA for IAM users", "PASS", "All IAM users with console password have MFA enabled.", {})


def run_checks(profile: str, region: str) -> Dict[str, Any]:
    session = _session(profile, region)

    findings: List[Finding] = []
    findings.append(check_sts(session))
    findings.append(check_guardduty(session))
    findings.append(check_cloudtrail(session, expected_trail_name="baseline-cloudtrail"))
    findings.append(check_log_group(session, name="/aws/cloudtrail/baseline", min_retention_days=30))
    findings.append(check_sns_topic(session, name="baseline-alerts"))
    findings.append(check_cloudwatch_alarms(session, names=["baseline-iam-changes-alarm", "baseline-root-login-alarm"]))
    findings.append(check_iam_mfa(session))

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1

    now = dt.datetime.now(dt.timezone.utc).isoformat()

    return {
        "meta": {
            "profile": profile,
            "region": region,
            "generated_at_utc": now,
        },
        "summary": {
            "pass": counts["PASS"],
            "warn": counts["WARN"],
            "fail": counts["FAIL"],
        },
        "findings": [asdict(f) for f in findings],
    }
