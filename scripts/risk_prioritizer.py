import csv
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DATA_FILES = [
    BASE / "data" / "sample_tenable_findings.csv",
    BASE / "data" / "sample_wiz_findings.csv",
]
OUTPUT = BASE / "outputs" / "prioritized_risk_report.csv"


def yes(value: str) -> bool:
    return str(value).strip().lower() in {"yes", "true", "1"}


def criticality_score(value: str) -> int:
    return {"low": 5, "medium": 10, "high": 20}.get(str(value).strip().lower(), 0)


def calculate_score(row: dict) -> int:
    score = float(row.get("cvss", 0)) * 10

    if yes(row.get("known_exploited", "No")):
        score += 30
    if yes(row.get("internet_facing", "No")):
        score += 25
    if yes(row.get("exploit_available", "No")):
        score += 15

    score += criticality_score(row.get("asset_criticality", "Low"))

    days_open = int(row.get("days_open", 0))
    if days_open > 90:
        score += 15
    elif days_open > 30:
        score += 10
    elif days_open > 14:
        score += 5

    attack_path = row.get("attack_path", "")
    if attack_path and attack_path.strip():
        score += 15

    return round(score)


def recommendation(row: dict, score: int) -> str:
    if score >= 150:
        return "Immediate remediation required; escalate to asset owner and leadership if SLA is at risk."
    if score >= 120:
        return "Prioritize this sprint; validate fix through rescan."
    if score >= 90:
        return "Schedule remediation based on SLA and business impact."
    return "Track through normal patching cycle."


def load_findings() -> list[dict]:
    findings = []
    for file in DATA_FILES:
        with file.open(newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row.setdefault("cloud_provider", "")
                row.setdefault("finding_type", "")
                row.setdefault("attack_path", "")
                score = calculate_score(row)
                row["business_risk_score"] = score
                row["recommendation"] = recommendation(row, score)
                findings.append(row)
    return sorted(findings, key=lambda x: x["business_risk_score"], reverse=True)


def write_report(findings: list[dict]) -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "business_risk_score", "asset_name", "source", "cve", "finding_type", "cvss", "severity",
        "internet_facing", "known_exploited", "exploit_available", "asset_criticality",
        "days_open", "attack_path", "remediation_status", "owner", "recommendation"
    ]
    with OUTPUT.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)


if __name__ == "__main__":
    findings = load_findings()
    write_report(findings)
    print(f"Created report: {OUTPUT}")
    print("Top 3 risks:")
    for item in findings[:3]:
        print(f"- {item['asset_name']} | {item['source']} | Score: {item['business_risk_score']} | {item['recommendation']}")
