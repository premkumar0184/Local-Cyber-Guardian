from datetime import datetime
from typing import List, Dict, Any, Union
from security_guardian.events.models import (
    Event, ProcessStartedEvent, NetworkListenerCreatedEvent, OutboundConnectionEvent,
    FileCreatedEvent, FileModifiedEvent, PersistenceChangedEvent
)

class EventNormalizer:
    @staticmethod
    def _get_timestamp() -> str:
        return datetime.utcnow().isoformat()

    def normalize_processes(self, raw_processes: List[Dict[str, Any]]) -> List[ProcessStartedEvent]:
        events = []
        for p in raw_processes:
            # Safely join cmdline if it's a list
            cmd = p.get('cmdline', [])
            cmd_str = " ".join(cmd) if cmd else ""
            event = ProcessStartedEvent(
                timestamp=self._get_timestamp(),
                pid=p['pid'],
                process=p['name'],
                parent_process=p['parent_name'],
                path=p['exe'],
                command_line=cmd_str
            )
            events.append(event)
        return events

    def normalize_network(self, raw_activity: List[Dict[str, Any]]) -> List[Union[NetworkListenerCreatedEvent, OutboundConnectionEvent]]:
        events = []
        for activity in raw_activity:
            if activity['activity_type'] == 'LISTEN':
                event = NetworkListenerCreatedEvent(
                    timestamp=self._get_timestamp(),
                    pid=activity['pid'],
                    process=activity['process_name'],
                    local_address=activity['laddr'],
                    local_port=activity['lport']
                )
                events.append(event)
            elif activity['activity_type'] == 'OUTBOUND':
                event = OutboundConnectionEvent(
                    timestamp=self._get_timestamp(),
                    pid=activity['pid'],
                    process=activity['process_name'],
                    remote_address=activity['raddr'],
                    remote_port=activity['rport']
                )
                events.append(event)
                events.append(event)
        return events

    def normalize_filesystem(self, raw_integrity: List[Dict[str, Any]]) -> List[Union[FileCreatedEvent, FileModifiedEvent]]:
        events = []
        for activity in raw_integrity:
            if activity['integrity_action'] == 'created':
                event = FileCreatedEvent(
                    timestamp=self._get_timestamp(),
                    pid=-1, # Unknown for watchdog
                    path=activity['path'],
                    is_executable=activity.get('is_executable', False)
                )
                events.append(event)
            elif activity['integrity_action'] == 'modified':
                event = FileModifiedEvent(
                    timestamp=self._get_timestamp(),
                    pid=-1,
                    path=activity['path'],
                    is_executable=activity.get('is_executable', False)
                )
                events.append(event)
        return events

    def normalize_persistence(self, raw_persistence: List[Dict[str, Any]]) -> List[PersistenceChangedEvent]:
        events = []
        for activity in raw_persistence:
            event = PersistenceChangedEvent(
                timestamp=self._get_timestamp(),
                pid=-1, # Unknown
                target=activity['path'],
                modification_type=activity['persistence_action']
            )
            events.append(event)
        return events
