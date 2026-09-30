import os
from typing import List, Dict, Any

class FileIntegrityCollector:
    def process_raw_events(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        integrity_events = []
        
        for event in raw_events:
            if event["is_directory"]:
                continue
                
            path = event["path"]
            action = event["action"]
            
            # We care about new files or modified files in /tmp, /var/tmp, or user home
            if "/tmp/" in path or "/var/tmp/" in path or path.startswith(os.path.expanduser("~")):
                if action in ["created", "modified"]:
                    # Check if executable
                    try:
                        if os.path.isfile(path) and os.access(path, os.X_OK):
                            integrity_events.append({
                                "integrity_action": action,
                                "path": path,
                                "is_executable": True
                            })
                    except OSError:
                        pass
                        
        return integrity_events
