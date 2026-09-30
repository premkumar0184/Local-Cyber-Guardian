from typing import List
from security_guardian.events.models import (
    Event, ProcessStartedEvent, NetworkListenerCreatedEvent, OutboundConnectionEvent,
    FileCreatedEvent, FileModifiedEvent, PersistenceChangedEvent
)
from security_guardian.detection.models import Incident

def evaluate_rules(event_buffer: List[Event]) -> List[Incident]:
    incidents = []
    
    suspicious_starts = []
    network_events = []
    global_file_events = []
    global_persistence_events = []
    
    for event in event_buffer:
        if isinstance(event, ProcessStartedEvent):
            path_str = (event.path or "") + " " + (event.command_line or "")
            if any(sp in path_str for sp in ["/tmp/", "/dev/shm/"]) or "unknown" in event.process:
                suspicious_starts.append(event)
        elif isinstance(event, (NetworkListenerCreatedEvent, OutboundConnectionEvent)):
            network_events.append(event)
        elif isinstance(event, (FileCreatedEvent, FileModifiedEvent)):
            global_file_events.append(event)
        elif isinstance(event, PersistenceChangedEvent):
            global_persistence_events.append(event)
            
    # Trigger an incident for EACH suspicious process if there is ANY correlated activity
    for p_start in suspicious_starts:
        if network_events or global_persistence_events:
            # Gather unique related events to avoid duplicates in the UI
            related_events = [p_start]
            for ev in (network_events + global_file_events + global_persistence_events):
                if ev not in related_events:
                    related_events.append(ev)
                    
            reasons = ["Suspicious executable: " + (p_start.path or "unknown")]
            
            if network_events:
                reasons.append("Correlated network activity detected")
            if global_persistence_events:
                reasons.append("Correlated persistence modification detected")
            if global_file_events:
                reasons.append("Correlated file integrity change detected")
                
            incidents.append(Incident(
                incident_id="",
                rule_id="SUSPICIOUS_PROCESS_CHAIN",
                severity="HIGH",
                reason=" + ".join(reasons),
                process_name=p_start.process,
                pid=p_start.pid,
                related_events=related_events
            ))
            
    return incidents
