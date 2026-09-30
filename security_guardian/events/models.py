from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class Event:
    timestamp: str
    pid: int
    event_type: str = field(init=False)

@dataclass
class ProcessStartedEvent(Event):
    process: str
    parent_process: str
    path: str
    command_line: str = ""
    
    def __post_init__(self):
        self.event_type = "PROCESS_STARTED"

@dataclass
class NetworkListenerCreatedEvent(Event):
    process: str
    local_address: str
    local_port: int
    
    def __post_init__(self):
        self.event_type = "NETWORK_LISTENER_CREATED"

@dataclass
class OutboundConnectionEvent(Event):
    process: str
    remote_address: str
    remote_port: int
    
    def __post_init__(self):
        self.event_type = "OUTBOUND_CONNECTION"

@dataclass
class PersistenceChangedEvent(Event):
    target: str
    modification_type: str
    
    def __post_init__(self):
        self.event_type = "PERSISTENCE_CHANGED"

@dataclass
class FileCreatedEvent(Event):
    path: str
    is_executable: bool
    
    def __post_init__(self):
        self.event_type = "FILE_CREATED"

@dataclass
class FileModifiedEvent(Event):
    path: str
    is_executable: bool
    
    def __post_init__(self):
        self.event_type = "FILE_MODIFIED"
