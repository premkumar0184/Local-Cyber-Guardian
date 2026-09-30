import os
from typing import List, Dict, Any

class PersistenceCollector:
    def __init__(self):
        self.persistence_indicators = [
            ".config/systemd/user/",
            "/etc/systemd/system/",
            ".config/autostart/",
            ".bashrc",
            ".bash_profile",
            ".ssh/authorized_keys",
            "cron.d/",
            "crontab"
        ]

    def process_raw_events(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        persistence_events = []
        
        for event in raw_events:
            if event["is_directory"]:
                continue
                
            path = event["path"]
            action = event["action"]
            
            for indicator in self.persistence_indicators:
                if indicator in path:
                    persistence_events.append({
                        "persistence_action": action,
                        "path": path,
                        "indicator": indicator
                    })
                    break # Only report once per path
                    
        return persistence_events
