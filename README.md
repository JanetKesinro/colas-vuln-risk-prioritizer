# Colas Vulnerability & Cloud Risk Prioritizer

<img width="1536" height="1024" alt="ChatGPT Image Jun 24, 2026, 03_01_36 PM" src="https://github.com/user-attachments/assets/abc9dac6-7fee-42ab-a430-22715bb95780" />


## Purpose
This project shows how I would support Colas as a Vulnerability Analyst using Tenable and Wiz data. The goal is to reduce noise from vulnerability scans and help remediation teams focus on the risks that matter most.

Colas USA supports local business networks across the United States and Colas Group operates globally across transportation infrastructure. That kind of distributed environment can create a large attack surface across endpoints, servers, cloud assets, subsidiaries, and business applications.

## Problem This Solves
Vulnerability teams often receive thousands of findings from tools like Tenable and Wiz. The challenge is not just finding vulnerabilities. The real challenge is deciding what to fix first based on real risk.

This project combines sample Tenable and Wiz findings and ranks them using practical risk factors such as:

- CVSS severity
- Known exploited vulnerability status
- Internet exposure
- Cloud asset criticality
- Business impact
- Exploit availability
- Age of vulnerability
- Remediation status

## Tools Represented
- Tenable / Nessus for vulnerability scanning
- Wiz for cloud security and attack path context
- Python for risk scoring and reporting
- CSV for easy data ingestion
- Markdown for executive-friendly reporting

## Why This Matters to Colas
A global construction and infrastructure company may have a mix of cloud systems, enterprise applications, remote users, operational locations, and business-critical systems. A vulnerability program should help teams quickly answer:

1. Which vulnerabilities create the highest business risk?
2. Which cloud assets are internet-facing or exposed?
3. Which findings are already known to be exploited?
4. Which remediation items should be handled first?
5. What can be reported clearly to leadership?

## Project Files

| File | Purpose |
|---|---|
| `data/sample_tenable_findings.csv` | Sample Tenable vulnerability findings |
| `data/sample_wiz_findings.csv` | Sample Wiz cloud risk findings |
| `scripts/risk_prioritizer.py` | Python script that combines and scores findings |
| `outputs/prioritized_risk_report.csv` | Final ranked risk report |
| `docs/interview_talking_points.md` | Simple talking points for the interview |

## How the Risk Score Works

<img width="1536" height="1024" alt="ChatGPT Image Jun 24, 2026, 03_03_02 PM" src="https://github.com/user-attachments/assets/56155114-f432-4483-b24f-4b3737eb7c84" />


The script calculates a business risk score using weighted factors:

- CVSS score
- CISA KEV / known exploited status
- Internet-facing exposure
- Critical asset status
- Exploit availability
- Vulnerability age
- Cloud attack path context from Wiz

The score helps separate urgent items from routine patching.

## Example Output
A critical internet-facing cloud VM with a known exploited vulnerability would rank above a medium vulnerability on a non-critical internal server.

## Disclaimer
This project uses mock data only. It does not contain or claim to contain any internal Colas data.
