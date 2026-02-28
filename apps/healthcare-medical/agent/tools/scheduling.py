from strands import tool
import json, random, uuid
from datetime import datetime, timedelta


@tool
def schedule_appointment(patient_id: str, provider_id: str, appointment_type: str, preferred_date: str) -> str:
    """Schedule a medical appointment for a patient with a specific provider.

    Books an appointment slot based on provider availability, appointment type,
    and patient preferences. Returns confirmation with preparation instructions.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').
        provider_id: Provider identifier (e.g., 'DR-CHEN', 'DR-PATEL').
        appointment_type: Type of appointment ('follow-up', 'annual-physical', 'urgent', 'specialist-referral', 'telehealth', 'lab-work', 'procedure').
        preferred_date: Preferred appointment date in YYYY-MM-DD format.

    Returns:
        JSON with appointment confirmation including date, time, location, provider, and preparation instructions.
    """
    provider_names = {
        "DR-CHEN": "Dr. Sarah Chen, MD - Internal Medicine",
        "DR-PATEL": "Dr. Priya Patel, MD - Pulmonology",
        "DR-WILSON": "Dr. James Wilson, MD - Gastroenterology",
        "DR-KIM": "Dr. Lisa Kim, MD - Psychiatry",
        "DR-GARCIA": "Dr. Carlos Garcia, MD - Cardiology",
        "NP-RODRIGUEZ": "Maria Rodriguez, NP - Primary Care",
    }

    prep_instructions = {
        "follow-up": [
            "Bring current medication list",
            "Bring any home monitoring logs (blood pressure, glucose)",
            "Prepare list of questions or concerns",
        ],
        "annual-physical": [
            "Fast for 12 hours prior (water is OK)",
            "Bring insurance card and photo ID",
            "Bring current medication list including supplements",
            "Wear comfortable clothing",
            "Prepare family medical history updates",
        ],
        "urgent": [
            "Arrive 15 minutes early for triage assessment",
            "Bring current medication list",
            "Describe symptom onset, duration, and severity",
        ],
        "specialist-referral": [
            "Bring referral paperwork from primary care",
            "Bring recent lab results and imaging",
            "Bring current medication list",
            "Arrive 30 minutes early for new patient paperwork",
        ],
        "telehealth": [
            "Ensure stable internet connection",
            "Test video and audio before appointment",
            "Have medication bottles available for review",
            "Find a private, well-lit location",
            "Video link will be sent 15 minutes before appointment",
        ],
        "lab-work": [
            "Fast for 12 hours if metabolic panel or lipid panel ordered",
            "Stay well hydrated (water is OK during fasting)",
            "Bring lab order form",
            "Wear loose-fitting sleeves for blood draw",
        ],
        "procedure": [
            "Review procedure-specific preparation instructions provided by office",
            "Arrange transportation (may not be able to drive after procedure)",
            "Fast as instructed by provider",
            "Bring signed consent forms",
        ],
    }

    provider_name = provider_names.get(provider_id.upper(), f"Provider {provider_id}")
    instructions = prep_instructions.get(appointment_type.lower(), ["Contact office for specific preparation instructions"])

    # Simulate finding an available slot near the preferred date
    try:
        pref_date = datetime.strptime(preferred_date, "%Y-%m-%d")
    except ValueError:
        pref_date = datetime.utcnow() + timedelta(days=7)

    offset_days = random.randint(0, 5)
    scheduled_date = pref_date + timedelta(days=offset_days)
    # Skip weekends
    while scheduled_date.weekday() >= 5:
        scheduled_date += timedelta(days=1)

    hour = random.choice([8, 9, 10, 11, 13, 14, 15, 16])
    minute = random.choice([0, 15, 30, 45])
    scheduled_time = f"{hour:02d}:{minute:02d}"

    duration_map = {
        "follow-up": 20, "annual-physical": 45, "urgent": 30,
        "specialist-referral": 45, "telehealth": 20, "lab-work": 15, "procedure": 60,
    }
    duration = duration_map.get(appointment_type.lower(), 30)

    appointment_id = f"APT-{uuid.uuid4().hex[:8].upper()}"

    return json.dumps({
        "appointment_id": appointment_id,
        "status": "CONFIRMED",
        "patient_id": patient_id,
        "provider": provider_name,
        "provider_id": provider_id,
        "appointment_type": appointment_type,
        "scheduled_date": scheduled_date.strftime("%Y-%m-%d"),
        "scheduled_time": scheduled_time,
        "duration_minutes": duration,
        "location": random.choice([
            "Main Campus - Building A, Suite 201",
            "Medical Office Building, 3rd Floor",
            "Outpatient Clinic - West Wing",
            "Telehealth (virtual)" if appointment_type.lower() == "telehealth" else "Lab Services - Ground Floor",
        ]),
        "preparation_instructions": instructions,
        "check_in": f"Arrive {15 if appointment_type.lower() != 'specialist-referral' else 30} minutes before appointment",
        "cancellation_policy": "Cancel or reschedule at least 24 hours in advance to avoid cancellation fee.",
        "confirmation_sent_to": random.choice(["Email and SMS", "Patient portal", "SMS only"]),
        "notes": f"{'New patient - extra time allocated. ' if appointment_type.lower() == 'specialist-referral' else ''}Appointment confirmed by scheduling system.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_provider_availability(provider_id: str, date_range: str) -> str:
    """Check provider availability for scheduling within a date range.

    Retrieves open appointment slots for the specified provider.

    Args:
        provider_id: Provider identifier (e.g., 'DR-CHEN', 'DR-PATEL').
        date_range: Date range in 'YYYY-MM-DD to YYYY-MM-DD' format or number of days (e.g., '7').

    Returns:
        JSON with available appointment slots grouped by date.
    """
    provider_names = {
        "DR-CHEN": {"name": "Dr. Sarah Chen, MD", "specialty": "Internal Medicine", "location": "Main Campus"},
        "DR-PATEL": {"name": "Dr. Priya Patel, MD", "specialty": "Pulmonology", "location": "Medical Office Building"},
        "DR-WILSON": {"name": "Dr. James Wilson, MD", "specialty": "Gastroenterology", "location": "Outpatient Clinic"},
        "DR-KIM": {"name": "Dr. Lisa Kim, MD", "specialty": "Psychiatry", "location": "Behavioral Health Center"},
        "DR-GARCIA": {"name": "Dr. Carlos Garcia, MD", "specialty": "Cardiology", "location": "Heart Center"},
        "NP-RODRIGUEZ": {"name": "Maria Rodriguez, NP", "specialty": "Primary Care", "location": "Main Campus"},
    }

    provider_info = provider_names.get(provider_id.upper(), {
        "name": f"Provider {provider_id}",
        "specialty": "General",
        "location": "Main Campus",
    })

    # Parse date range
    try:
        if "to" in date_range:
            parts = date_range.split("to")
            start_date = datetime.strptime(parts[0].strip(), "%Y-%m-%d")
            end_date = datetime.strptime(parts[1].strip(), "%Y-%m-%d")
        else:
            num_days = int(date_range.strip())
            start_date = datetime.utcnow() + timedelta(days=1)
            end_date = start_date + timedelta(days=num_days)
    except (ValueError, IndexError):
        start_date = datetime.utcnow() + timedelta(days=1)
        end_date = start_date + timedelta(days=7)

    availability = []
    current_date = start_date
    while current_date <= end_date:
        if current_date.weekday() < 5:  # Weekdays only
            slots = []
            morning_slots = random.sample([
                "08:00", "08:30", "09:00", "09:30", "10:00", "10:30", "11:00", "11:30"
            ], k=random.randint(1, 5))
            afternoon_slots = random.sample([
                "13:00", "13:30", "14:00", "14:30", "15:00", "15:30", "16:00", "16:30"
            ], k=random.randint(1, 5))

            for time_str in sorted(morning_slots + afternoon_slots):
                slots.append({
                    "time": time_str,
                    "duration_minutes": random.choice([15, 20, 30, 45]),
                    "slot_type": random.choice(["in-person", "in-person", "telehealth"]),
                })

            availability.append({
                "date": current_date.strftime("%Y-%m-%d"),
                "day_of_week": current_date.strftime("%A"),
                "available_slots": slots,
                "total_open_slots": len(slots),
            })
        current_date += timedelta(days=1)

    total_slots = sum(day["total_open_slots"] for day in availability)

    return json.dumps({
        "provider_id": provider_id,
        "provider": provider_info,
        "date_range": {
            "start": start_date.strftime("%Y-%m-%d"),
            "end": end_date.strftime("%Y-%m-%d"),
        },
        "availability": availability,
        "summary": {
            "total_available_days": len(availability),
            "total_available_slots": total_slots,
            "earliest_available": availability[0]["availability"][0]["time"] if availability and availability[0].get("available_slots") else "None",
        } if availability else {"message": "No available slots in the requested date range."},
        "booking_note": "To book, use schedule_appointment with desired date and time.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def get_upcoming_appointments(patient_id: str) -> str:
    """Get all upcoming scheduled appointments for a patient.

    Retrieves the patient's appointment calendar including provider details,
    appointment type, location, and preparation reminders.

    Args:
        patient_id: Patient identifier (e.g., 'PAT-001234').

    Returns:
        JSON with list of upcoming appointments sorted by date.
    """
    appointment_types = ["Follow-up", "Annual Physical", "Lab Work", "Specialist Consultation",
                         "Telehealth Visit", "Imaging", "Procedure"]
    providers = [
        {"name": "Dr. Sarah Chen, MD", "specialty": "Internal Medicine"},
        {"name": "Dr. Priya Patel, MD", "specialty": "Pulmonology"},
        {"name": "Dr. James Wilson, MD", "specialty": "Gastroenterology"},
        {"name": "Dr. Carlos Garcia, MD", "specialty": "Cardiology"},
        {"name": "Maria Rodriguez, NP", "specialty": "Primary Care"},
    ]
    locations = [
        "Main Campus - Building A, Suite 201",
        "Medical Office Building, 3rd Floor",
        "Outpatient Clinic - West Wing",
        "Lab Services - Ground Floor",
        "Imaging Center - 2nd Floor",
    ]

    num_appointments = random.randint(1, 5)
    appointments = []
    for _ in range(num_appointments):
        appt_date = datetime.utcnow() + timedelta(days=random.randint(1, 90))
        while appt_date.weekday() >= 5:
            appt_date += timedelta(days=1)
        hour = random.choice([8, 9, 10, 11, 13, 14, 15, 16])
        minute = random.choice([0, 15, 30, 45])
        provider = random.choice(providers)
        appt_type = random.choice(appointment_types)

        appointments.append({
            "appointment_id": f"APT-{uuid.uuid4().hex[:8].upper()}",
            "date": appt_date.strftime("%Y-%m-%d"),
            "time": f"{hour:02d}:{minute:02d}",
            "day_of_week": appt_date.strftime("%A"),
            "appointment_type": appt_type,
            "provider": provider,
            "location": "Telehealth (virtual)" if "Telehealth" in appt_type else random.choice(locations),
            "duration_minutes": random.choice([15, 20, 30, 45, 60]),
            "status": random.choice(["Confirmed", "Confirmed", "Confirmed", "Pending Confirmation"]),
            "reminder_sent": random.choice([True, False]),
            "notes": random.choice([
                "Fasting required", "Bring medication list", "Follow-up from last visit",
                "Pre-procedure consultation", "", ""
            ]),
        })

    appointments.sort(key=lambda a: a["date"])

    return json.dumps({
        "patient_id": patient_id,
        "total_upcoming": len(appointments),
        "appointments": appointments,
        "next_appointment": appointments[0] if appointments else None,
        "reminders": {
            "pending_reminders": sum(1 for a in appointments if not a["reminder_sent"]),
            "message": "Some appointments have not received reminders yet." if any(not a["reminder_sent"] for a in appointments) else "All reminders sent.",
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@tool
def send_appointment_reminder(appointment_id: str) -> str:
    """Send a reminder notification for an upcoming appointment.

    Dispatches a reminder via the patient's preferred communication channel
    (SMS, email, or patient portal notification).

    Args:
        appointment_id: Appointment identifier (e.g., 'APT-1A2B3C4D').

    Returns:
        JSON with reminder delivery confirmation and details.
    """
    hour = random.choice([8, 9, 10, 11, 13, 14, 15])
    minute = random.choice([0, 15, 30, 45])
    appt_date = (datetime.utcnow() + timedelta(days=random.randint(1, 14)))
    while appt_date.weekday() >= 5:
        appt_date += timedelta(days=1)

    channel = random.choice(["SMS", "Email", "Patient Portal", "SMS and Email"])

    return json.dumps({
        "appointment_id": appointment_id,
        "reminder_status": "SENT",
        "delivery_channel": channel,
        "sent_at": datetime.utcnow().isoformat() + "Z",
        "appointment_details": {
            "date": appt_date.strftime("%Y-%m-%d"),
            "time": f"{hour:02d}:{minute:02d}",
            "provider": random.choice(["Dr. Sarah Chen, MD", "Dr. Priya Patel, MD", "Dr. James Wilson, MD"]),
            "location": random.choice(["Main Campus - Building A", "Medical Office Building", "Telehealth (virtual)"]),
            "type": random.choice(["Follow-up", "Lab Work", "Annual Physical", "Specialist Consultation"]),
        },
        "reminder_message": f"Reminder: You have an appointment on {appt_date.strftime('%B %d, %Y')} at {hour:02d}:{minute:02d}. "
                           f"Please arrive 15 minutes early. Reply CONFIRM to confirm or call (555) 123-4567 to reschedule.",
        "patient_response_required": True,
        "follow_up_reminder": f"Second reminder scheduled for {(appt_date - timedelta(days=1)).strftime('%Y-%m-%d')} if no confirmation received.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
