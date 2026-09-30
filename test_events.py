from security_guardian.events.models import ProcessStartedEvent, OutboundConnectionEvent, PersistenceChangedEvent
from security_guardian.events.normalizer import EventNormalizer

p = ProcessStartedEvent(timestamp="123", pid=1, process="a", parent_process="b", path="c")
print(p.event_type)

o = OutboundConnectionEvent(timestamp="123", pid=1, process="a", remote_address="b", remote_port=80)
print(o.event_type)

print("Events instantiating successfully!")
