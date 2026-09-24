"""
Capacity-Constrained Investigation Queue Prioritizer
Project Code: HTH-CS-07
Dataset: CMU CERT r4.2
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

# Fixed investigator capacity slots according to specification
INVESTIGATOR_CAPACITY = 3

class IncidentTriageItem(BaseModel):
    user_id: str
    employee_name: str
    role: str
    department: str
    risk_score: int
    risk_level: str
    egress_volume_mb: float
    egress_score: float
    priority_rank: float
    slot_assignment: str  # ACTIVE_SLOT_1, ACTIVE_SLOT_2, ACTIVE_SLOT_3, or DEFERRED_BACKLOG
    deferral_reason: Optional[str] = None
    action_decision: str

def compute_egress_volume_score(egress_mb: float) -> float:
    """
    Normalizes data egress volume into a 0-100 scale:
    - 0 to 5 MB: 5 - 20 points
    - 5 to 50 MB: 20 - 60 points
    - 50 to 500+ MB: 60 - 100 points
    """
    if egress_mb <= 0.05:
        return 5.0
    elif egress_mb <= 5.0:
        return min(25.0, 5.0 + (egress_mb / 5.0) * 20.0)
    elif egress_mb <= 50.0:
        return min(65.0, 25.0 + ((egress_mb - 5.0) / 45.0) * 40.0)
    else:
        return min(100.0, 65.0 + ((egress_mb - 50.0) / 400.0) * 35.0)

def rank_incident_queue(assessments: List[Dict[str, Any]], 
                        capacity: int = INVESTIGATOR_CAPACITY) -> Dict[str, Any]:
    """
    Prioritizes incidents under capacity constraint (K = 3) using:
    PriorityRank = (RiskScore * 0.7) + (DataEgressVolumeScore * 0.3)
    
    Splits into:
    1. Active Investigation Slots (Top K)
    2. Deferred Backlog with explicit deferral reasons
    """
    triage_items: List[IncidentTriageItem] = []

    for item in assessments:
        r_score = float(item.get("risk_score", 0))
        egress_mb = float(item.get("total_recent_egress_mb", item.get("egress_volume_mb", 0.0)))
        egress_score = compute_egress_volume_score(egress_mb)
        
        # Core Priority Formula from specification
        priority_rank = round((r_score * 0.7) + (egress_score * 0.3), 2)
        
        triage_items.append(IncidentTriageItem(
            user_id=item.get("user_id", "UNKNOWN"),
            employee_name=item.get("employee_name", item.get("user_id", "")),
            role=item.get("role", "Employee"),
            department=item.get("department", "Corporate"),
            risk_score=int(r_score),
            risk_level=item.get("risk_level", "LOW"),
            egress_volume_mb=egress_mb,
            egress_score=round(egress_score, 1),
            priority_rank=priority_rank,
            slot_assignment="UNASSIGNED",
            deferral_reason=None,
            action_decision=item.get("action_decision", "ACCESS APPROVED")
        ))

    # Sort descending by PriorityRank
    triage_items.sort(key=lambda x: x.priority_rank, reverse=True)

    active_slots: List[IncidentTriageItem] = []
    deferred_backlog: List[IncidentTriageItem] = []

    # Assign top K to active slots, rest to deferred backlog
    for idx, incident in enumerate(triage_items):
        if idx < capacity and incident.risk_score > 30:
            incident.slot_assignment = f"Active Workbench Slot #{idx + 1}"
            active_slots.append(incident)
        else:
            position_in_backlog = len(deferred_backlog) + 1
            if incident.risk_score > 30:
                reason = f"Capacity limit reached ({capacity}/{capacity} analyst workbenches occupied); held in position #{position_in_backlog} of backlog pending triage completion."
            else:
                reason = f"Benign operational profile (Score {incident.risk_score}); automatically filtered to backlog position #{position_in_backlog}."
            
            incident.slot_assignment = f"Deferred Backlog (Pos #{position_in_backlog})"
            incident.deferral_reason = reason
            deferred_backlog.append(incident)

    return {
        "capacity_limit": capacity,
        "active_occupied": len(active_slots),
        "available_slots": max(0, capacity - len(active_slots)),
        "active_investigation_slots": [i.model_dump() for i in active_slots],
        "deferred_backlog": [i.model_dump() for i in deferred_backlog],
        "total_triaged": len(triage_items)
    }
