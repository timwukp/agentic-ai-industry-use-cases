from strands import tool
import json
import random
from datetime import datetime, timedelta


@tool
def analyze_defect_pattern(product_line: str, period: str) -> str:
    """Analyze defect patterns and distribution for a product line.

    Examines defect data across the product line to identify frequency distributions,
    common defect types, and correlations with production parameters.

    Args:
        product_line: The product line identifier to analyze defects for.
        period: The analysis period (e.g., 'Q1-2024', 'last_30_days', 'FY-2023').

    Returns:
        JSON string with defect pattern analysis including distributions and correlations.
    """
    total_units_produced = random.randint(10000, 500000)
    total_defects = random.randint(int(total_units_produced * 0.005), int(total_units_produced * 0.05))
    defect_rate_pct = round(total_defects / total_units_produced * 100, 3)

    defect_types = [
        {"type": "Dimensional out-of-spec", "count": random.randint(10, 200), "pct": 0},
        {"type": "Surface finish defect", "count": random.randint(5, 150), "pct": 0},
        {"type": "Material contamination", "count": random.randint(3, 80), "pct": 0},
        {"type": "Assembly misalignment", "count": random.randint(5, 100), "pct": 0},
        {"type": "Weld/joint failure", "count": random.randint(2, 60), "pct": 0},
        {"type": "Coating/plating defect", "count": random.randint(3, 90), "pct": 0},
        {"type": "Electrical continuity failure", "count": random.randint(2, 50), "pct": 0},
    ]

    selected_defects = random.sample(defect_types, random.randint(4, 6))
    total_count = sum(d["count"] for d in selected_defects)
    for d in selected_defects:
        d["pct"] = round(d["count"] / total_count * 100, 1)
    selected_defects.sort(key=lambda x: x["count"], reverse=True)

    shifts = ["Day Shift (6AM-2PM)", "Swing Shift (2PM-10PM)", "Night Shift (10PM-6AM)"]
    shift_correlation = [
        {"shift": s, "defect_rate_pct": round(random.uniform(0.5, 5.0), 2)} for s in shifts
    ]

    return json.dumps({
        "product_line": product_line,
        "period": period,
        "summary": {
            "total_units_produced": total_units_produced,
            "total_defects": total_defects,
            "defect_rate_pct": defect_rate_pct,
            "target_defect_rate_pct": 1.0,
            "status": "WITHIN_TARGET" if defect_rate_pct <= 1.0 else "ABOVE_TARGET",
        },
        "defect_distribution": selected_defects,
        "pareto_analysis": {
            "top_3_defects_pct": round(sum(d["pct"] for d in selected_defects[:3]), 1),
            "recommendation": "Focus on top 3 defect types for 80/20 improvement",
        },
        "correlations": {
            "shift_analysis": shift_correlation,
            "worst_performing_shift": max(shift_correlation, key=lambda x: x["defect_rate_pct"])["shift"],
            "machine_correlation": random.choice([
                "Machine M-07 shows 2x average defect rate",
                "No significant machine correlation detected",
                "CNC cluster B has elevated dimensional defects",
            ]),
        },
        "trend": random.choice(["IMPROVING", "WORSENING", "STABLE"]),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def perform_root_cause_analysis(defect_id: str) -> str:
    """Perform multi-factor root cause analysis using 5-Why and Fishbone methods.

    Conducts structured root cause investigation combining the 5-Why
    drill-down technique with Ishikawa (fishbone) diagram categorization
    to identify the fundamental cause of a defect.

    Args:
        defect_id: The defect identifier to perform root cause analysis on.

    Returns:
        JSON string with root cause findings from multiple analysis methods.
    """
    defect_description = random.choice([
        "Dimensional variation exceeding tolerance on critical feature",
        "Intermittent surface finish roughness on machined parts",
        "Weld porosity detected in structural joints",
        "Coating adhesion failure after thermal cycling",
        "Assembly torque values inconsistent across batch",
    ])

    five_whys = [
        {"level": 1, "question": "Why did the defect occur?",
         "answer": random.choice([
             "Part dimension was out of tolerance",
             "Surface contamination was present",
             "Process parameter drifted from specification",
         ])},
        {"level": 2, "question": "Why was it out of tolerance?",
         "answer": random.choice([
             "Tool wear exceeded replacement threshold",
             "Material batch had inconsistent properties",
             "Machine calibration had drifted",
         ])},
        {"level": 3, "question": "Why was this not detected earlier?",
         "answer": random.choice([
             "Inspection frequency was insufficient",
             "SPC charts not reviewed in real-time",
             "Operator training on detection was incomplete",
         ])},
        {"level": 4, "question": "Why was the control inadequate?",
         "answer": random.choice([
             "Preventive maintenance schedule was extended",
             "Process capability study was outdated",
             "Control plan did not cover this failure mode",
         ])},
        {"level": 5, "question": "Why was the system gap not addressed?",
         "answer": random.choice([
             "Resource constraints deferred maintenance improvements",
             "Risk assessment did not identify this vulnerability",
             "Management of change process was not triggered",
         ])},
    ]

    fishbone_categories = {
        "Man (People)": random.sample([
            "Operator fatigue during extended shifts",
            "Training gap on updated procedure",
            "Insufficient experience on new equipment",
        ], random.randint(1, 2)),
        "Machine": random.sample([
            "Tool wear beyond specification",
            "Calibration drift over time",
            "Vibration from adjacent equipment",
            "Insufficient preventive maintenance",
        ], random.randint(1, 2)),
        "Material": random.sample([
            "Incoming material variation",
            "Storage conditions affecting properties",
            "Supplier batch inconsistency",
        ], random.randint(1, 2)),
        "Method": random.sample([
            "Work instruction ambiguity",
            "Process parameter not optimized",
            "Inspection method sensitivity insufficient",
        ], random.randint(1, 2)),
        "Environment": random.sample([
            "Temperature fluctuation in production area",
            "Humidity outside recommended range",
            "Particulate contamination from nearby process",
        ], 1),
    }

    return json.dumps({
        "defect_id": defect_id,
        "defect_description": defect_description,
        "five_why_analysis": five_whys,
        "root_cause_identified": five_whys[-1]["answer"],
        "fishbone_analysis": fishbone_categories,
        "contributing_factors": random.randint(2, 5),
        "confidence_level": round(random.uniform(0.7, 0.95), 2),
        "verification_method": random.choice([
            "Controlled experiment confirmed cause-effect",
            "Statistical correlation analysis supports finding",
            "Process simulation validated hypothesis",
        ]),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_8d_report(defect_id: str) -> str:
    """Generate an 8D (Eight Disciplines) problem-solving report.

    Creates a structured 8D report following the standard methodology for
    systematic problem resolution, from team formation through verification
    of corrective actions.

    Args:
        defect_id: The defect identifier to generate the 8D report for.

    Returns:
        JSON string with complete 8D report structure and findings.
    """
    report_id = f"8D-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    return json.dumps({
        "report_id": report_id,
        "defect_id": defect_id,
        "status": random.choice(["IN_PROGRESS", "COMPLETE"]),
        "disciplines": {
            "D1_team": {
                "team_lead": "Quality Engineering Manager",
                "members": random.sample([
                    "Process Engineer",
                    "Quality Inspector",
                    "Production Supervisor",
                    "Maintenance Technician",
                    "Design Engineer",
                    "Supplier Quality Engineer",
                ], random.randint(3, 5)),
            },
            "D2_problem_description": {
                "what": random.choice([
                    "Critical dimension out of tolerance on machined component",
                    "Surface defect on final assembly exterior panels",
                    "Functional test failure at end-of-line station",
                ]),
                "when": (datetime.utcnow() - timedelta(days=random.randint(3, 30))).strftime("%Y-%m-%d"),
                "where": random.choice(["Line 3, Station 7", "CNC Cell B", "Assembly Area 2", "Final Test"]),
                "magnitude": f"{random.randint(5, 50)} units affected, {round(random.uniform(0.5, 5), 1)}% of production",
            },
            "D3_interim_containment": {
                "action": random.choice([
                    "100% inspection of suspect lot implemented",
                    "Production quarantined pending investigation",
                    "Sort and rework of affected inventory",
                ]),
                "effective_date": (datetime.utcnow() - timedelta(days=random.randint(1, 10))).strftime("%Y-%m-%d"),
                "customer_protected": True,
            },
            "D4_root_cause": {
                "primary_cause": random.choice([
                    "Tool wear exceeded monitoring threshold without detection",
                    "Process parameter drift due to environmental change",
                    "Material property variation from new supplier lot",
                ]),
                "verification": "Cause confirmed via controlled experiment",
            },
            "D5_corrective_actions": [
                {
                    "action": random.choice([
                        "Implement real-time tool wear monitoring with auto-stop",
                        "Update process parameters with tighter control limits",
                        "Add incoming material verification step",
                    ]),
                    "owner": "Process Engineering",
                    "due_date": (datetime.utcnow() + timedelta(days=random.randint(7, 30))).strftime("%Y-%m-%d"),
                    "status": random.choice(["COMPLETE", "IN_PROGRESS"]),
                },
                {
                    "action": "Update control plan and PFMEA",
                    "owner": "Quality Engineering",
                    "due_date": (datetime.utcnow() + timedelta(days=random.randint(14, 45))).strftime("%Y-%m-%d"),
                    "status": random.choice(["COMPLETE", "IN_PROGRESS", "NOT_STARTED"]),
                },
            ],
            "D6_verification": {
                "method": "30-day production monitoring with enhanced sampling",
                "results": random.choice(["Defect eliminated - 0 recurrences", "Monitoring in progress"]),
                "effective": random.choice([True, None]),
            },
            "D7_preventive_actions": [
                "Apply lessons learned to similar process across other lines",
                "Update preventive maintenance schedule for affected equipment",
                "Enhance operator training program with new failure mode",
            ],
            "D8_closure": {
                "team_recognized": True,
                "lessons_learned_documented": True,
                "closure_date": (datetime.utcnow() + timedelta(days=random.randint(30, 60))).strftime("%Y-%m-%d"),
            },
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def recommend_corrective_action(defect_id: str) -> str:
    """Recommend corrective and preventive actions (CAPA) for a defect.

    Generates prioritized CAPA recommendations based on root cause analysis,
    defect severity, and implementation feasibility.

    Args:
        defect_id: The defect identifier to generate CAPA recommendations for.

    Returns:
        JSON string with prioritized corrective and preventive actions.
    """
    corrective_actions = random.sample([
        {
            "action": "Install automated in-process inspection (vision system)",
            "type": "CORRECTIVE",
            "priority": "HIGH",
            "cost_estimate": round(random.uniform(15000, 75000), 2),
            "implementation_weeks": random.randint(2, 8),
            "effectiveness_pct": round(random.uniform(85, 99), 1),
        },
        {
            "action": "Implement SPC with real-time alerting on critical parameters",
            "type": "CORRECTIVE",
            "priority": "HIGH",
            "cost_estimate": round(random.uniform(5000, 20000), 2),
            "implementation_weeks": random.randint(1, 4),
            "effectiveness_pct": round(random.uniform(75, 95), 1),
        },
        {
            "action": "Redesign tooling fixture for improved repeatability",
            "type": "CORRECTIVE",
            "priority": "MEDIUM",
            "cost_estimate": round(random.uniform(8000, 40000), 2),
            "implementation_weeks": random.randint(4, 12),
            "effectiveness_pct": round(random.uniform(80, 95), 1),
        },
        {
            "action": "Revise work instructions with visual aids and checkpoints",
            "type": "CORRECTIVE",
            "priority": "MEDIUM",
            "cost_estimate": round(random.uniform(1000, 5000), 2),
            "implementation_weeks": random.randint(1, 3),
            "effectiveness_pct": round(random.uniform(60, 80), 1),
        },
    ], random.randint(2, 3))

    preventive_actions = random.sample([
        {
            "action": "Extend FMEA to cover newly identified failure mode across product family",
            "type": "PREVENTIVE",
            "priority": "HIGH",
            "cost_estimate": round(random.uniform(3000, 10000), 2),
            "implementation_weeks": random.randint(2, 6),
        },
        {
            "action": "Enhance supplier qualification process with capability requirements",
            "type": "PREVENTIVE",
            "priority": "MEDIUM",
            "cost_estimate": round(random.uniform(2000, 8000), 2),
            "implementation_weeks": random.randint(4, 12),
        },
        {
            "action": "Implement predictive maintenance for critical equipment",
            "type": "PREVENTIVE",
            "priority": "HIGH",
            "cost_estimate": round(random.uniform(20000, 100000), 2),
            "implementation_weeks": random.randint(8, 24),
        },
        {
            "action": "Conduct design-of-experiments to optimize process window",
            "type": "PREVENTIVE",
            "priority": "MEDIUM",
            "cost_estimate": round(random.uniform(5000, 25000), 2),
            "implementation_weeks": random.randint(3, 8),
        },
    ], random.randint(2, 3))

    total_investment = sum(a["cost_estimate"] for a in corrective_actions + preventive_actions)
    estimated_annual_savings = round(total_investment * random.uniform(1.5, 5.0), 2)

    return json.dumps({
        "defect_id": defect_id,
        "corrective_actions": corrective_actions,
        "preventive_actions": preventive_actions,
        "investment_summary": {
            "total_estimated_cost": round(total_investment, 2),
            "estimated_annual_savings": estimated_annual_savings,
            "payback_period_months": round(total_investment / (estimated_annual_savings / 12), 1),
            "roi_pct": round((estimated_annual_savings - total_investment) / total_investment * 100, 1),
        },
        "implementation_plan": {
            "immediate_actions": [a["action"] for a in corrective_actions if a["priority"] == "HIGH"],
            "short_term_actions": [a["action"] for a in corrective_actions if a["priority"] == "MEDIUM"],
            "long_term_actions": [a["action"] for a in preventive_actions],
        },
        "verification_plan": {
            "method": "Monitor defect rate for 90 days post-implementation",
            "success_criteria": "Defect rate reduced by minimum 80%",
            "review_date": (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"),
        },
        "recommended_at": datetime.utcnow().isoformat() + "Z",
    })
