import time
from collections import deque
from typing import List, Optional
from datetime import datetime

from security_guardian.events.models import Event
from security_guardian.detection.models import Incident
from security_guardian.detection.rules import evaluate_rules

class EventCorrelator:
    def __init__(self, buffer_seconds: int = 300):
        self.buffer_seconds = buffer_seconds
        self.event_buffer: deque[Event] = deque()
        self.incident_count = 0
        self.reported_incidents = {} # pid -> timestamp

    def add_events(self, events: List[Event]) -> List[Incident]:
        incidents = []
        now = datetime.utcnow()
        
        # Add new events
        for event in events:
            self.event_buffer.append(event)
            
        # Clean up old events
        self._cleanup_buffer(now)
        
        # Evaluate rules when new events are added
        if events:
            new_incidents = evaluate_rules(list(self.event_buffer))
            for inc in new_incidents:
                # Deduplication: don't alert on the same PID in a 60 second window
                last_reported = self.reported_incidents.get(inc.pid, 0)
                if now.timestamp() - last_reported > 60:
                    self.reported_incidents[inc.pid] = now.timestamp()
                    self.incident_count += 1
                    inc.incident_id = f"INC-{self.incident_count:04d}"
                    incidents.append(inc)
                
        return incidents

    def _cleanup_buffer(self, now: datetime):
        while self.event_buffer:
            oldest_event = self.event_buffer[0]
            try:
                event_time = datetime.fromisoformat(oldest_event.timestamp)
                if (now - event_time).total_seconds() > self.buffer_seconds:
                    self.event_buffer.popleft()
                else:
                    break
            except ValueError:
                self.event_buffer.popleft() # invalid timestamp
