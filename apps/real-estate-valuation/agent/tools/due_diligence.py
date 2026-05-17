"""Due diligence tools for the Real Estate Valuation Assistant.

Provides legal document review, title status checking, environmental risk
assessment, and due diligence checklist generation for property transactions.
"""

import json
import random
from datetime import datetime, timedelta

from strands import tool


@tool
def review_legal_documents(property_id: str, doc_type: str) -> str:
    """Review legal documents and extract key terms, risks, and obligations.

    Analyzes property-related legal documents including deeds, contracts,
    easements, and zoning documents to extract material terms and flag
    potential issues.

    Args:
        property_id: The property identifier the documents relate to.
        doc_type: Type of document to review (e.g., 'deed', 'purchase_agreement', 'easement', 'zoning').

    Returns:
        JSON string with extracted key terms, identified risks, and review status.
    """
    doc_types_info = {
        "deed": {
            "document_name": "Warranty Deed",
            "key_terms": [
                {"term": "Grantor/Grantee names", "value": "Verified and correct"},
                {"term": "Legal description", "value": "Metes and bounds, Lot 14, Block 7"},
                {"term": "Deed type", "value": random.choice(["General Warranty", "Special Warranty", "Quitclaim"])},
                {"term": "Consideration", "value": f"${random.randint(100000, 5000000):,}"},
                {"term": "Recording information", "value": f"Book {random.randint(100, 999)}, Page {random.randint(1, 500)}"},
            ],
        },
        "purchase_agreement": {
            "document_name": "Purchase and Sale Agreement",
            "key_terms": [
                {"term": "Purchase price", "value": f"${random.randint(500000, 50000000):,}"},
                {"term": "Earnest money deposit", "value": f"${random.randint(10000, 500000):,}"},
                {"term": "Closing date", "value": (datetime.utcnow() + timedelta(days=random.randint(30, 90))).strftime("%Y-%m-%d")},
                {"term": "Contingencies", "value": random.sample(["Financing", "Inspection", "Appraisal", "Title"], random.randint(2, 4))},
                {"term": "Representations and warranties", "value": f"{random.randint(10, 25)} standard representations"},
            ],
        },
        "easement": {
            "document_name": "Easement Agreement",
            "key_terms": [
                {"term": "Easement type", "value": random.choice(["Utility", "Access", "Conservation", "Drainage"])},
                {"term": "Affected area", "value": f"{random.randint(100, 5000)} sq ft"},
                {"term": "Duration", "value": random.choice(["Perpetual", "25 years", "99 years"])},
                {"term": "Maintenance responsibility", "value": random.choice(["Dominant estate", "Servient estate", "Shared"])},
                {"term": "Restrictions", "value": random.choice(["No permanent structures", "Vegetation limits", "Access hours restricted"])},
            ],
        },
        "zoning": {
            "document_name": "Zoning Compliance Certificate",
            "key_terms": [
                {"term": "Zoning classification", "value": random.choice(["C-2 Commercial", "R-3 Residential", "M-1 Industrial", "PUD"])},
                {"term": "Permitted uses", "value": random.sample(["Office", "Retail", "Multi-family", "Restaurant", "Medical"], 3)},
                {"term": "FAR (Floor Area Ratio)", "value": round(random.uniform(1.0, 5.0), 1)},
                {"term": "Height restriction", "value": f"{random.randint(35, 200)} feet"},
                {"term": "Setback requirements", "value": f"Front: {random.randint(10, 30)}ft, Side: {random.randint(5, 15)}ft"},
            ],
        },
    }

    doc_info = doc_types_info.get(doc_type, doc_types_info["deed"])

    risks = random.sample([
        {"risk": "Ambiguous boundary description in legal description", "severity": "MEDIUM"},
        {"risk": "Potential title defect from prior conveyance gap", "severity": "HIGH"},
        {"risk": "Non-conforming use may not be grandfathered", "severity": "MEDIUM"},
        {"risk": "Easement conflicts with planned development", "severity": "HIGH"},
        {"risk": "Missing subordination language in existing mortgage", "severity": "LOW"},
        {"risk": "Environmental covenant restricts future use", "severity": "MEDIUM"},
    ], random.randint(0, 3))

    return json.dumps({
        "property_id": property_id,
        "document_type": doc_type,
        "document_name": doc_info["document_name"],
        "review_status": "COMPLETE",
        "key_terms": doc_info["key_terms"],
        "risks_identified": risks,
        "overall_risk_level": "HIGH" if any(r["severity"] == "HIGH" for r in risks) else "MEDIUM" if risks else "LOW",
        "recommendations": [
            "Obtain title insurance for identified defects" if any(r["severity"] == "HIGH" for r in risks) else "Standard closing conditions appropriate",
            "Request seller representations addressing flagged items",
        ],
        "reviewed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def check_title_status(property_id: str) -> str:
    """Check property title status including liens, encumbrances, and chain of title.

    Performs a comprehensive title search to identify any clouds on title,
    outstanding liens, encumbrances, or breaks in the chain of ownership.

    Args:
        property_id: The property identifier to check title status for.

    Returns:
        JSON string with title status, identified issues, and marketability assessment.
    """
    title_clear = random.random() > 0.3

    liens = []
    if not title_clear or random.random() > 0.5:
        possible_liens = [
            {"type": "Mortgage", "holder": "First National Bank", "amount": round(random.uniform(100000, 2000000), 2),
             "recording_date": (datetime.utcnow() - timedelta(days=random.randint(365, 3650))).strftime("%Y-%m-%d")},
            {"type": "Property Tax Lien", "holder": "County Tax Assessor", "amount": round(random.uniform(5000, 50000), 2),
             "recording_date": (datetime.utcnow() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d")},
            {"type": "Mechanic's Lien", "holder": "ABC Construction LLC", "amount": round(random.uniform(10000, 200000), 2),
             "recording_date": (datetime.utcnow() - timedelta(days=random.randint(30, 180))).strftime("%Y-%m-%d")},
            {"type": "HOA Assessment Lien", "holder": "Parkview HOA", "amount": round(random.uniform(1000, 15000), 2),
             "recording_date": (datetime.utcnow() - timedelta(days=random.randint(60, 365))).strftime("%Y-%m-%d")},
            {"type": "Judgment Lien", "holder": "Smith v. Current Owner", "amount": round(random.uniform(25000, 500000), 2),
             "recording_date": (datetime.utcnow() - timedelta(days=random.randint(90, 730))).strftime("%Y-%m-%d")},
        ]
        liens = random.sample(possible_liens, random.randint(1, 3))

    encumbrances = random.sample([
        {"type": "Utility Easement", "details": "10ft strip along north boundary", "impact": "LOW"},
        {"type": "CC&Rs", "details": "Homeowner association covenants and restrictions", "impact": "LOW"},
        {"type": "Conservation Easement", "details": "Wetland buffer zone - no development", "impact": "HIGH"},
        {"type": "Right of Way", "details": "Public access through northeast corner", "impact": "MEDIUM"},
    ], random.randint(0, 2))

    total_lien_amount = sum(lien["amount"] for lien in liens)
    marketable = len(liens) <= 1 and not any(e["impact"] == "HIGH" for e in encumbrances)

    return json.dumps({
        "property_id": property_id,
        "title_status": "CLEAR" if title_clear and not liens else "ENCUMBERED",
        "marketable_title": marketable,
        "chain_of_title": {
            "years_searched": random.choice([30, 40, 50, 60]),
            "breaks_found": 0 if title_clear else random.randint(0, 1),
            "conveyances_reviewed": random.randint(3, 12),
        },
        "liens": liens,
        "total_lien_amount": total_lien_amount,
        "encumbrances": encumbrances,
        "title_insurance_recommendation": {
            "standard_coverage": True,
            "extended_coverage_recommended": not marketable,
            "estimated_premium": round(random.uniform(1000, 10000), 2),
        },
        "exceptions_to_coverage": [
            "Standard printed exceptions",
            "Rights of parties in possession",
            "Survey matters",
        ],
        "checked_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def assess_environmental_risk(property_id: str) -> str:
    """Assess environmental risk for a property (Phase I ESA screening level).

    Performs a preliminary environmental screening to identify recognized
    environmental conditions (RECs) that may require further investigation
    through a formal Phase I Environmental Site Assessment.

    Args:
        property_id: The property identifier to assess environmental risk for.

    Returns:
        JSON string with environmental risk assessment including RECs and recommendations.
    """
    risk_level = random.choice(["LOW", "MODERATE", "HIGH"])

    recs = []
    possible_recs = [
        {"finding": "Historical dry cleaning operation on adjacent parcel", "type": "REC",
         "concern": "Potential chlorinated solvent migration"},
        {"finding": "Underground storage tank (UST) records for prior gas station", "type": "REC",
         "concern": "Petroleum hydrocarbon contamination risk"},
        {"finding": "Former industrial use identified in Sanborn maps", "type": "HREC",
         "concern": "Historical manufacturing may have released contaminants"},
        {"finding": "Property within 1/4 mile of Superfund site", "type": "REC",
         "concern": "Groundwater plume migration potential"},
        {"finding": "Asbestos-containing materials likely in pre-1980 construction", "type": "CREC",
         "concern": "ACM management required during renovation"},
        {"finding": "Elevated radon potential based on geologic mapping", "type": "DE_MINIMIS",
         "concern": "Radon mitigation may be needed"},
    ]

    if risk_level == "HIGH":
        recs = random.sample(possible_recs, random.randint(2, 4))
    elif risk_level == "MODERATE":
        recs = random.sample(possible_recs, random.randint(1, 2))
    else:
        recs = random.sample([p for p in possible_recs if p["type"] in ["DE_MINIMIS", "HREC"]], random.randint(0, 1))

    regulatory_databases = {
        "EPA NPL/Superfund": random.choice(["NO_LISTING", "NO_LISTING", "LISTED_NEARBY"]),
        "RCRA Generators": random.choice(["NO_LISTING", "LISTED", "NO_LISTING"]),
        "State UST Registry": random.choice(["NO_LISTING", "HISTORICAL_CLOSED", "ACTIVE_NEARBY"]),
        "State Brownfields": random.choice(["NO_LISTING", "NO_LISTING", "LISTED"]),
        "Tribal Lands": "NO_LISTING",
    }

    return json.dumps({
        "property_id": property_id,
        "risk_level": risk_level,
        "screening_type": "Phase I ESA Preliminary Screening",
        "recognized_environmental_conditions": recs,
        "regulatory_database_review": regulatory_databases,
        "site_history": {
            "current_use": random.choice(["Commercial office", "Retail", "Vacant land", "Industrial"]),
            "prior_uses": random.sample(["Agricultural", "Commercial", "Industrial", "Residential", "Vacant"], 2),
            "years_researched": random.randint(30, 60),
        },
        "recommendation": (
            "Phase II ESA recommended - subsurface investigation needed" if risk_level == "HIGH"
            else "Phase I ESA sufficient - monitor conditions" if risk_level == "MODERATE"
            else "Low environmental risk - standard due diligence adequate"
        ),
        "estimated_phase2_cost": round(random.uniform(15000, 75000), 2) if risk_level in ["HIGH", "MODERATE"] else None,
        "assessed_at": datetime.utcnow().isoformat() + "Z",
    })


@tool
def generate_dd_checklist(transaction_type: str, property_type: str) -> str:
    """Generate a comprehensive due diligence checklist for a transaction.

    Creates a tailored checklist of required due diligence items based on
    the transaction type and property type, with status tracking and
    responsible party assignments.

    Args:
        transaction_type: Type of transaction (e.g., 'acquisition', 'disposition', 'refinance', 'development').
        property_type: Type of property (e.g., 'office', 'retail', 'industrial', 'multifamily', 'land').

    Returns:
        JSON string with structured due diligence checklist including categories and items.
    """
    checklist_id = f"DDC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    categories = [
        {
            "category": "Legal/Title",
            "items": [
                {"item": "Title commitment/preliminary report", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Title Company", "deadline_days": 14},
                {"item": "Survey (ALTA/NSPS)", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Surveyor", "deadline_days": 21},
                {"item": "Zoning confirmation letter", "status": random.choice(["COMPLETE", "PENDING"]),
                 "responsible": "Zoning Attorney", "deadline_days": 14},
                {"item": "Lease review and abstraction", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Legal Counsel", "deadline_days": 21},
            ],
        },
        {
            "category": "Physical/Environmental",
            "items": [
                {"item": "Phase I Environmental Site Assessment", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Environmental Consultant", "deadline_days": 28},
                {"item": "Property Condition Assessment (PCA)", "status": random.choice(["COMPLETE", "IN_PROGRESS"]),
                 "responsible": "Engineering Firm", "deadline_days": 21},
                {"item": "Seismic risk assessment", "status": random.choice(["COMPLETE", "N/A", "PENDING"]),
                 "responsible": "Structural Engineer", "deadline_days": 21},
                {"item": "ADA compliance review", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "ADA Consultant", "deadline_days": 14},
            ],
        },
        {
            "category": "Financial",
            "items": [
                {"item": "Historical operating statements (3 years)", "status": random.choice(["COMPLETE", "IN_PROGRESS"]),
                 "responsible": "Seller/Broker", "deadline_days": 7},
                {"item": "Rent roll verification", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Asset Manager", "deadline_days": 14},
                {"item": "Tax return review", "status": random.choice(["COMPLETE", "PENDING"]),
                 "responsible": "CPA/Tax Advisor", "deadline_days": 14},
                {"item": "Capital expenditure history and projections", "status": random.choice(["COMPLETE", "IN_PROGRESS"]),
                 "responsible": "Property Manager", "deadline_days": 14},
            ],
        },
        {
            "category": "Regulatory/Compliance",
            "items": [
                {"item": "Building code compliance verification", "status": random.choice(["COMPLETE", "IN_PROGRESS", "PENDING"]),
                 "responsible": "Code Consultant", "deadline_days": 21},
                {"item": "Fire/life safety inspection", "status": random.choice(["COMPLETE", "PENDING"]),
                 "responsible": "Fire Marshal", "deadline_days": 14},
                {"item": "Certificate of Occupancy", "status": random.choice(["COMPLETE", "PENDING"]),
                 "responsible": "Municipality", "deadline_days": 7},
                {"item": "Insurance requirements review", "status": random.choice(["COMPLETE", "IN_PROGRESS"]),
                 "responsible": "Insurance Broker", "deadline_days": 14},
            ],
        },
    ]

    total_items = sum(len(c["items"]) for c in categories)
    complete_items = sum(1 for c in categories for i in c["items"] if i["status"] == "COMPLETE")

    return json.dumps({
        "checklist_id": checklist_id,
        "transaction_type": transaction_type,
        "property_type": property_type,
        "overall_progress_pct": round(complete_items / total_items * 100, 1),
        "categories": categories,
        "summary": {
            "total_items": total_items,
            "complete": complete_items,
            "in_progress": sum(1 for c in categories for i in c["items"] if i["status"] == "IN_PROGRESS"),
            "pending": sum(1 for c in categories for i in c["items"] if i["status"] == "PENDING"),
            "not_applicable": sum(1 for c in categories for i in c["items"] if i["status"] == "N/A"),
        },
        "critical_path_items": [
            i["item"] for c in categories for i in c["items"]
            if i["status"] == "PENDING" and i["deadline_days"] <= 14
        ],
        "target_completion_date": (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })
