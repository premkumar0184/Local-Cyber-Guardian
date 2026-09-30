from dataclasses import dataclass, field
from typing import List, Dict, Any
from security_guardian.events.models import Event

@dataclass
class Incident:
    incident_id: str
    rule_id: str
    severity: str
    reason: str
    process_name: str
    pid: int
    related_events: List[Event] = field(default_factory=list)
    confidence: float = 1.0 # Deterministic confidence is typically 1.0, AI can change this later
    ai_assessment: Dict[str, Any] = field(default_factory=dict)
