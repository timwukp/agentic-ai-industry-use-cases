"""Gateway target: scheduling — appointments, availability, reminders.

All scheduling data is a deterministic simulation seeded from the function
inputs (stable within a calendar day).
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

PROVIDER_DIRECTORY = {
    "DR-CHEN": {"name": "Dr. Sarah Chen, MD", "specialty": "Internal Medicine", "location": "Main Campus"},
    "DR-PATEL": {"name": "Dr. Priya Patel, MD", "specialty": "Pulmonology", "location": "Medical Office Building"},
    "DR-WILSON": {"name": "Dr. James Wilson, MD", "specialty": "Gastroenterology", "location": "Outpatient Clinic"},
    "DR-KIM": {"name": "Dr. Lisa Kim, MD", "specialty": "Psychiatry", "location": "Behavioral Health Center"},
    "DR-GARCIA": {"name": "Dr. Carlos Garcia, MD", "specialty": "Cardiology", "location": "Heart Center"},
    "NP-RODRIGUEZ": {"name": "Maria Rodriguez, NP", "specialty": "Primary Care", "location": "Main Campus"},
}

PREP_INSTRUCTIONS = {
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

DURATION_MAP = {
    "follow-up": 20, "annual-physical": 45, "urgent": 30,
    "specialist-referral": 45, "telehealth": 20, "lab-work": 15, "procedure": 60,
}

LOCATIONS = [
    "Main Campus - Building A, Suite 201",
    "Medical Office Building, 3rd Floor",
    "Outpatient Clinic - West Wing",
    "Lab Services - Ground Floor",
]


def _rng(*parts) -> random.Random:
    seed = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return random.Random(int(seed[:16], 16))


def _today() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day)


def _skip_weekend(d: datetime) -> datetime:
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


def schedule_appointment(patient_id: str, provider_id: str, appointment_type: str,
                         preferred_date: str) -> dict:
    appointment_type = appointment_type.lower()
    if appointment_type not in PREP_INSTRUCTIONS:
        return tool_error(f"Invalid appointment_type: {appointment_type}",
                          valid=sorted(PREP_INSTRUCTIONS))
    provider = PROVIDER_DIRECTORY.get(provider_id.upper())
    provider_name = (f"{provider['name']} - {provider['specialty']}" if provider
                     else f"Provider {provider_id}")
    try:
        pref_date = datetime.strptime(preferred_date, "%Y-%m-%d")
    except ValueError:
        return tool_error("preferred_date must be in YYYY-MM-DD format")

    r = _rng("schedule", patient_id, provider_id.upper(), appointment_type, preferred_date)
    scheduled_date = _skip_weekend(pref_date + timedelta(days=r.randint(0, 5)))
    scheduled_time = f"{r.choice([8, 9, 10, 11, 13, 14, 15, 16]):02d}:{r.choice([0, 15, 30, 45]):02d}"
    location = ("Telehealth (virtual)" if appointment_type == "telehealth"
                else r.choice(LOCATIONS))

    return tool_ok({
        "appointment_id": f"APT-{r.randrange(16 ** 8):08X}",
        "status": "CONFIRMED",
        "patient_id": patient_id,
        "provider": provider_name,
        "provider_id": provider_id,
        "appointment_type": appointment_type,
        "scheduled_date": scheduled_date.strftime("%Y-%m-%d"),
        "scheduled_time": scheduled_time,
        "duration_minutes": DURATION_MAP.get(appointment_type, 30),
        "location": location,
        "preparation_instructions": PREP_INSTRUCTIONS[appointment_type],
        "check_in": f"Arrive {30 if appointment_type == 'specialist-referral' else 15} "
                    "minutes before appointment",
        "cancellation_policy": "Cancel or reschedule at least 24 hours in advance to avoid a fee.",
        "note": "Demo scheduling system: booking is simulated.",
    }, simulated=True)


def get_provider_availability(provider_id: str, date_range: str = "7") -> dict:
    provider = PROVIDER_DIRECTORY.get(provider_id.upper(), {
        "name": f"Provider {provider_id}", "specialty": "General", "location": "Main Campus"})
    today = _today()
    try:
        if "to" in date_range:
            start_s, end_s = (p.strip() for p in date_range.split("to")[:2])
            start_date = datetime.strptime(start_s, "%Y-%m-%d")
            end_date = datetime.strptime(end_s, "%Y-%m-%d")
        else:
            start_date = today + timedelta(days=1)
            end_date = start_date + timedelta(days=int(date_range.strip()))
    except (ValueError, IndexError):
        start_date = today + timedelta(days=1)
        end_date = start_date + timedelta(days=7)
    end_date = min(end_date, start_date + timedelta(days=30))

    morning = ["08:00", "08:30", "09:00", "09:30", "10:00", "10:30", "11:00", "11:30"]
    afternoon = ["13:00", "13:30", "14:00", "14:30", "15:00", "15:30", "16:00", "16:30"]

    availability = []
    current = start_date
    while current <= end_date:
        if current.weekday() < 5:
            r = _rng("availability", provider_id.upper(), current.strftime("%Y-%m-%d"))
            slots = sorted(r.sample(morning, k=r.randint(1, 5)) +
                           r.sample(afternoon, k=r.randint(1, 5)))
            slot_objs = [{"time": t,
                          "duration_minutes": r.choice([15, 20, 30, 45]),
                          "slot_type": r.choice(["in-person", "in-person", "telehealth"])}
                         for t in slots]
            availability.append({
                "date": current.strftime("%Y-%m-%d"),
                "day_of_week": current.strftime("%A"),
                "available_slots": slot_objs,
                "total_open_slots": len(slot_objs),
            })
        current += timedelta(days=1)

    return tool_ok({
        "provider_id": provider_id,
        "provider": provider,
        "date_range": {"start": start_date.strftime("%Y-%m-%d"),
                       "end": end_date.strftime("%Y-%m-%d")},
        "availability": availability,
        "summary": ({
            "total_available_days": len(availability),
            "total_available_slots": sum(d["total_open_slots"] for d in availability),
            "earliest_available": availability[0]["available_slots"][0]["time"],
        } if availability else {"message": "No available slots in the requested date range."}),
        "booking_note": "To book, use schedule_appointment with the desired date.",
    }, simulated=True)


def get_upcoming_appointments(patient_id: str) -> dict:
    today = _today()
    r = _rng("upcoming", patient_id, today.strftime("%Y-%m-%d"))
    appointment_types = ["Follow-up", "Annual Physical", "Lab Work", "Specialist Consultation",
                         "Telehealth Visit", "Imaging", "Procedure"]
    providers = [{"name": v["name"], "specialty": v["specialty"]}
                 for v in PROVIDER_DIRECTORY.values()]

    appointments = []
    for _ in range(r.randint(1, 5)):
        appt_date = _skip_weekend(today + timedelta(days=r.randint(1, 90)))
        appt_type = r.choice(appointment_types)
        appointments.append({
            "appointment_id": f"APT-{r.randrange(16 ** 8):08X}",
            "date": appt_date.strftime("%Y-%m-%d"),
            "time": f"{r.choice([8, 9, 10, 11, 13, 14, 15, 16]):02d}:{r.choice([0, 15, 30, 45]):02d}",
            "day_of_week": appt_date.strftime("%A"),
            "appointment_type": appt_type,
            "provider": r.choice(providers),
            "location": "Telehealth (virtual)" if "Telehealth" in appt_type else r.choice(LOCATIONS),
            "duration_minutes": r.choice([15, 20, 30, 45, 60]),
            "status": r.choice(["Confirmed", "Confirmed", "Confirmed", "Pending Confirmation"]),
            "reminder_sent": r.choice([True, False]),
        })
    appointments.sort(key=lambda a: a["date"])
    pending = sum(1 for a in appointments if not a["reminder_sent"])

    return tool_ok({
        "patient_id": patient_id,
        "total_upcoming": len(appointments),
        "appointments": appointments,
        "next_appointment": appointments[0] if appointments else None,
        "reminders": {
            "pending_reminders": pending,
            "message": ("Some appointments have not received reminders yet."
                        if pending else "All reminders sent."),
        },
    }, simulated=True)


def send_appointment_reminder(appointment_id: str) -> dict:
    today = _today()
    r = _rng("reminder", appointment_id, today.strftime("%Y-%m-%d"))
    appt_date = _skip_weekend(today + timedelta(days=r.randint(1, 14)))
    time_str = f"{r.choice([8, 9, 10, 11, 13, 14, 15]):02d}:{r.choice([0, 15, 30, 45]):02d}"

    return tool_ok({
        "appointment_id": appointment_id,
        "reminder_status": "SENT",
        "delivery_channel": r.choice(["SMS", "Email", "Patient Portal", "SMS and Email"]),
        "appointment_details": {
            "date": appt_date.strftime("%Y-%m-%d"),
            "time": time_str,
            "provider": r.choice(["Dr. Sarah Chen, MD", "Dr. Priya Patel, MD",
                                  "Dr. James Wilson, MD"]),
            "location": r.choice(["Main Campus - Building A", "Medical Office Building",
                                  "Telehealth (virtual)"]),
        },
        "reminder_message": (f"Reminder: You have an appointment on "
                             f"{appt_date.strftime('%B %d, %Y')} at {time_str}. "
                             "Please arrive 15 minutes early. Reply CONFIRM to confirm."),
        "patient_response_required": True,
        "note": "Demo scheduling system: reminder delivery is simulated.",
    }, simulated=True)


TOOLS = {
    "schedule_appointment": schedule_appointment,
    "get_provider_availability": get_provider_availability,
    "get_upcoming_appointments": get_upcoming_appointments,
    "send_appointment_reminder": send_appointment_reminder,
}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
