🛡️ AWS Security Baseline  
Infrastructure as Code • Automated Verification • Real Alerts

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 OVERVIEW

This project implements a practical AWS security baseline and validates it through automated, live checks.

The focus is not only on deploying security services, but on proving that:
• services are enabled  
• integrations work end-to-end  
• alerts are actually delivered  

This mirrors real-world cloud security engineering, not a lab demo.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 OBJECTIVES

✔ Deploy core AWS security controls  
✔ Verify configuration via live AWS APIs  
✔ Demonstrate real alert delivery (SNS email)  
✔ Keep the repository 100% secret-free  
✔ Provide auditable evidence (screenshots)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧱 INFRASTRUCTURE (Terraform)

• AWS GuardDuty enabled  
• EventBridge rule for GuardDuty findings  
• SNS topic (baseline-alerts)  
• Email subscription for alerts  
• CloudTrail enabled and logging  
• CloudWatch log retention configured  
• Security-related CloudWatch alarms  

All resources are deployed using Infrastructure as Code.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧪 VERIFICATION (Python Audit CLI)

A lightweight Python CLI validates the baseline using live AWS API calls.

Checks include:
• GuardDuty status  
• CloudTrail logging  
• Log retention policy  
• SNS topic existence  
• Alarm health  
• IAM MFA enforcement  
• STS caller identity  

Outputs:
• scan.json (machine-readable)  
• report.md (human-readable)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧭 ARCHITECTURE

GuardDuty  
  ↓  
EventBridge Rule  
  ↓  
SNS Topic  
  ↓  
Email Notification  

The audit CLI independently verifies each component.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📸 EVIDENCE

All evidence screenshots are stored in:

docs/screenshots/

1. EventBridge rule (GuardDuty → SNS)  
2. Rule verified via AWS CLI  
3. SNS target attached to rule  
4. Audit CLI scan & report  
5. SNS topic with confirmed subscription  
6. GuardDuty finding in AWS Console  
7. Delivered alert email (SNS)

Screenshots are reviewed and redacted where required.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▶️ QUICK START

cd python-cli  
python -m venv .venv  

Windows:
.\.venv\Scripts\Activate.ps1  

pip install -r requirements.txt  

python -m aws_audit scan --profile <PROFILE> --region eu-central-1  
python -m aws_audit report --format markdown  

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔐 SECURITY & DATA HANDLING

This repository does NOT contain:
✖ AWS access keys  
✖ Secrets or tokens  
✖ SSO cache files  
✖ Terraform state files  
✖ Generated scan outputs  

Sensitive artifacts are blocked via .gitignore.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💼 WHY THIS PROJECT MATTERS

This project demonstrates:
• AWS-native security services  
• Infrastructure as Code best practices  
• Verification-driven security  
• Clean separation of deployment and audit  
• Professional handling of sensitive data  

It reflects how cloud security is implemented in production environments.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 LICENSE

MIT
