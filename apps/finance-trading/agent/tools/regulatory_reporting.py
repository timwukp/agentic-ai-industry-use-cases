from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def generate_regulatory_report(report_type: str, period: str) -> str:
    """Generate a regulatory compliance report for specified framework and period.

    Produces formatted regulatory reports for Basel III, MiFID II, or Dodd-Frank
    compliance requirements including key metrics and attestations.

    Args:
        report_type: The regulatory framework (e.g., 'Basel III', 'MiFID II', 'Dodd-Frank').
        period: The reporting period (e.g., 'Q1-2024', '2024-01', 'FY-2023').

    Returns:
        JSON string with formatted regulatory report data including metrics, status, and findings.
    """
    report_id = f"REG-{report_type.replace(' ', '')}-{period}-{random.randint(1000, 9999)}"

    if "Basel" in report_type:
        metrics = {
            "cet1_ratio_pct": round(random.uniform(10, 16), 2),
            "tier1_ratio_pct": round(random.uniform(11, 18), 2),
            "total_capital_ratio_pct": round(random.uniform(13, 20), 2),
            "leverage_ratio_pct": round(random.uniform(4, 7), 2),
            "lcr_pct": round(random.uniform(100, 160), 1),
            "nsfr_pct": round(random.uniform(100, 140), 1),
            "risk_weighted_assets": round(random.uniform(1e9, 5e10), 2),
        }
        framework_version = "Basel III / CRD IV"
    elif "MiFID" in report_type:
        metrics = {
            "best_execution_compliance_pct": round(random.uniform(95, 100), 2),
            "trade_reporting_timeliness_pct": round(random.uniform(97, 100), 2),
            "client_categorization_accuracy_pct": round(random.uniform(98, 100), 1),
            "transaction_reports_submitted": random.randint(10000, 500000),
            "late_reports": random.randint(0, 50),
            "order_record_keeping_compliance": random.choice([True, True, True, False]),
            "conflicts_of_interest_disclosures": random.randint(5, 30),
        }
        framework_version = "MiFID II / MiFIR"
    else:
        metrics = {
            "volcker_rule_compliance": random.choice([True, True, False]),
            "swap_margin_posted": round(random.uniform(1e6, 1e9), 2),
            "clearing_obligation_met": True,
            "trade_execution_compliance_pct": round(random.uniform(96, 100), 2),
            "reporting_completeness_pct": round(random.uniform(97, 100), 2),
            "concentration_limit_breaches": random.randint(0, 3),
            "stress_test_capital_buffer": round(random.uniform(2e8, 5e9), 2),
        }
        framework_version = "Dodd-Frank Wall Street Reform Act"

    findings = []
    possible_findings = [
        {"finding": "Minor data quality issue in trade reporting", "severity": "LOW", "remediation_due": "30 days"},
        {"finding": "Documentation gap in client suitability assessment", "severity": "MEDIUM", "remediation_due": "60 days"},
        {"finding": "Threshold breach in concentration limits", "severity": "HIGH", "remediation_due": "immediate"},
        {"finding": "Incomplete audit trail for manual overrides", "severity": "MEDIUM", "remediation_due": "45 days"},
    ]
    findings = random.sample(possible_findings, random.randint(0, 2))

    return json.dumps({
        "report_id": report_id,
        "report_type": report_type,
        "framework_version": framework_version,
        "period": period,
        "status": "COMPLIANT" if len(findings) == 0 else "COMPLIANT_WITH_FINDINGS",
        "metrics": metrics,
        "findings": findings,
        "attestation": {
            "attested_by": "Chief Compliance Officer",
            "attestation_date": datetime.utcnow().strftime("%Y-%m-%d"),
            "next_review_date": (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_compliance_gaps(portfolio_id: str) -> str:
    """Identify compliance gaps in a portfolio against current regulations.

    Scans portfolio positions and trading activity for regulatory breaches,
    limit exceedances, and documentation gaps.

    Args:
        portfolio_id: The portfolio identifier to check for compliance gaps.

    Returns:
        JSON string with identified compliance gaps, severity levels, and remediation steps.
    """
    all_gaps = [
        {
            "gap_type": "CONCENTRATION_LIMIT",
            "description": "Single issuer exposure exceeds 10% limit",
            "regulation": "UCITS Directive",
            "severity": "HIGH",
            "current_value": f"{round(random.uniform(10.1, 15.0), 1)}%",
            "limit": "10%",
            "remediation": "Reduce position to below concentration threshold",
        },
        {
            "gap_type": "LIQUIDITY_COVERAGE",
            "description": "Insufficient liquid assets for redemption coverage",
            "regulation": "SEC Rule 22e-4",
            "severity": "MEDIUM",
            "current_value": f"{round(random.uniform(70, 85), 1)}%",
            "limit": "85%",
            "remediation": "Increase allocation to highly liquid instruments",
        },
        {
            "gap_type": "LEVERAGE_LIMIT",
            "description": "Gross leverage approaching regulatory maximum",
            "regulation": "AIFMD",
            "severity": "MEDIUM",
            "current_value": f"{round(random.uniform(180, 200), 1)}%",
            "limit": "200%",
            "remediation": "Monitor and prepare deleveraging plan",
        },
        {
            "gap_type": "SHORT_SELLING_DISCLOSURE",
            "description": "Net short position disclosure threshold breached",
            "regulation": "EU Short Selling Regulation",
            "severity": "HIGH",
            "current_value": f"{round(random.uniform(0.5, 1.0), 2)}%",
            "limit": "0.5%",
            "remediation": "File disclosure with relevant authority within T+1",
        },
        {
            "gap_type": "DOCUMENTATION",
            "description": "Missing pre-trade compliance attestation for OTC derivatives",
            "regulation": "EMIR",
            "severity": "LOW",
            "current_value": "3 trades missing",
            "limit": "0 tolerance",
            "remediation": "Complete retroactive documentation and update workflow",
        },
        {
            "gap_type": "ESG_DISCLOSURE",
            "description": "SFDR Article 8 fund missing sustainability metrics update",
            "regulation": "SFDR",
            "severity": "MEDIUM",
            "current_value": "Q3 report pending",
            "limit": "Quarterly disclosure",
            "remediation": "Complete sustainability metrics calculation and publish",
        },
    ]

    num_gaps = random.randint(0, 4)
    identified_gaps = random.sample(all_gaps, num_gaps)

    overall_status = "COMPLIANT" if num_gaps == 0 else "ACTION_REQUIRED" if any(
        g["severity"] == "HIGH" for g in identified_gaps
    ) else "MONITORING"

    return json.dumps({
        "portfolio_id": portfolio_id,
        "overall_status": overall_status,
        "total_gaps_found": num_gaps,
        "gaps": identified_gaps,
        "regulations_checked": [
            "UCITS Directive", "AIFMD", "EMIR", "MiFID II",
            "SEC Rules", "SFDR", "EU Short Selling Regulation",
        ],
        "last_full_review": (datetime.utcnow() - timedelta(days=random.randint(7, 60))).strftime("%Y-%m-%d"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def monitor_rule_changes(jurisdiction: str) -> str:
    """Check for recent regulatory rule changes in a specified jurisdiction.

    Monitors regulatory bodies for new rules, amendments, consultations, and
    enforcement actions that may impact trading operations.

    Args:
        jurisdiction: The regulatory jurisdiction to monitor (e.g., 'US', 'EU', 'UK', 'APAC').

    Returns:
        JSON string with recent rule changes, effective dates, and impact assessments.
    """
    rule_changes_by_jurisdiction = {
        "US": [
            {"regulator": "SEC", "topic": "Climate Disclosure Rules", "type": "NEW_RULE"},
            {"regulator": "CFTC", "topic": "Digital Asset Derivatives Framework", "type": "PROPOSED_RULE"},
            {"regulator": "OCC", "topic": "CRA Modernization Final Rule", "type": "AMENDMENT"},
            {"regulator": "FINRA", "topic": "Enhanced Reporting for Dark Pool Activity", "type": "NEW_RULE"},
            {"regulator": "Federal Reserve", "topic": "Stress Test Methodology Update", "type": "GUIDANCE"},
        ],
        "EU": [
            {"regulator": "ESMA", "topic": "DORA Implementation Technical Standards", "type": "NEW_RULE"},
            {"regulator": "EBA", "topic": "Basel III Final Implementation (CRR III)", "type": "AMENDMENT"},
            {"regulator": "ECB", "topic": "Climate Risk Supervisory Expectations", "type": "GUIDANCE"},
            {"regulator": "ESMA", "topic": "MiCA Crypto-Asset Regulation", "type": "NEW_RULE"},
            {"regulator": "EIOPA", "topic": "Solvency II Review Delegated Acts", "type": "AMENDMENT"},
        ],
        "UK": [
            {"regulator": "FCA", "topic": "Consumer Duty Implementation Review", "type": "GUIDANCE"},
            {"regulator": "PRA", "topic": "Basel 3.1 UK Implementation", "type": "NEW_RULE"},
            {"regulator": "FCA", "topic": "Sustainability Disclosure Requirements", "type": "PROPOSED_RULE"},
            {"regulator": "BoE", "topic": "Digital Pound Consultation", "type": "CONSULTATION"},
            {"regulator": "FCA", "topic": "Overseas Fund Regime Equivalence", "type": "AMENDMENT"},
        ],
        "APAC": [
            {"regulator": "MAS", "topic": "Stablecoin Regulatory Framework", "type": "NEW_RULE"},
            {"regulator": "JFSA", "topic": "Digital Securities Offering Rules", "type": "AMENDMENT"},
            {"regulator": "HKMA", "topic": "Virtual Asset Service Provider Licensing", "type": "NEW_RULE"},
            {"regulator": "ASIC", "topic": "Design and Distribution Obligations Update", "type": "GUIDANCE"},
            {"regulator": "SFC", "topic": "OTC Derivatives Reporting Phase 5", "type": "NEW_RULE"},
        ],
    }

    changes = rule_changes_by_jurisdiction.get(jurisdiction, rule_changes_by_jurisdiction["US"])
    selected_changes = random.sample(changes, random.randint(2, min(4, len(changes))))

    enriched_changes = []
    for change in selected_changes:
        effective_date = datetime.utcnow() + timedelta(days=random.randint(-30, 365))
        enriched_changes.append({
            **change,
            "effective_date": effective_date.strftime("%Y-%m-%d"),
            "impact_level": random.choice(["HIGH", "MEDIUM", "LOW"]),
            "action_required": random.choice([
                "Policy update required",
                "System changes needed",
                "Staff training required",
                "No immediate action",
                "Board notification required",
            ]),
            "compliance_deadline": (effective_date - timedelta(days=random.randint(30, 90))).strftime("%Y-%m-%d"),
        })

    return json.dumps({
        "jurisdiction": jurisdiction,
        "total_changes": len(enriched_changes),
        "rule_changes": enriched_changes,
        "monitoring_sources": ["Official Gazettes", "Regulator Websites", "Thomson Reuters Regulatory Intelligence"],
        "last_checked": datetime.utcnow().isoformat() + "Z",
    })


@tool
def validate_report_data(report_id: str) -> str:
    """Validate report data completeness and accuracy before regulatory submission.

    Performs data quality checks, cross-references with source systems, and verifies
    calculations to ensure the report meets submission standards.

    Args:
        report_id: The identifier of the report to validate.

    Returns:
        JSON string with validation results, data quality score, and any issues found.
    """
    all_checks = [
        {"check": "Data completeness - all required fields populated", "category": "COMPLETENESS"},
        {"check": "Cross-reference with trade repository", "category": "ACCURACY"},
        {"check": "Calculation verification - ratios and aggregations", "category": "ACCURACY"},
        {"check": "Temporal consistency - no future-dated records", "category": "CONSISTENCY"},
        {"check": "Reference data alignment - LEI, ISIN codes valid", "category": "VALIDITY"},
        {"check": "Threshold validation - values within expected ranges", "category": "REASONABLENESS"},
        {"check": "Prior period reconciliation", "category": "CONSISTENCY"},
        {"check": "Duplicate record detection", "category": "UNIQUENESS"},
    ]

    results = []
    total_issues = 0
    for check in all_checks:
        passed = random.random() > 0.2
        issues = 0 if passed else random.randint(1, 5)
        total_issues += issues
        results.append({
            **check,
            "status": "PASS" if passed else "FAIL",
            "issues_found": issues,
            "details": None if passed else f"Found {issues} record(s) failing validation",
        })

    total_records = random.randint(1000, 50000)
    quality_score = round((total_records - total_issues) / total_records * 100, 2)

    submission_ready = quality_score >= 99.5 and all(r["status"] == "PASS" for r in results if r["category"] == "ACCURACY")

    return json.dumps({
        "report_id": report_id,
        "validation_status": "PASS" if submission_ready else "REQUIRES_REMEDIATION",
        "submission_ready": submission_ready,
        "data_quality_score_pct": quality_score,
        "total_records_validated": total_records,
        "total_issues_found": total_issues,
        "validation_checks": results,
        "recommendation": "Ready for submission" if submission_ready else "Address failed checks before submission",
        "validated_at": datetime.utcnow().isoformat() + "Z",
    })
