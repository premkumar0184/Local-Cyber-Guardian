import os
import queue
from typing import List, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class _FSHandler(FileSystemEventHandler):
    def __init__(self, q: queue.Queue):
        self.q = q
        
    def on_created(self, event):
        self.q.put({"action": "created", "path": event.src_path, "is_directory": event.is_directory})
        
    def on_modified(self, event):
        self.q.put({"action": "modified", "path": event.src_path, "is_directory": event.is_directory})
        
    def on_deleted(self, event):
        self.q.put({"action": "deleted", "path": event.src_path, "is_directory": event.is_directory})

class FilesystemCollector:
    def __init__(self):
        self.event_queue = queue.Queue()
        self.observer = Observer()
        self.handler = _FSHandler(self.event_queue)
        
        # Determine paths to monitor
        home = os.path.expanduser("~")
        paths_to_monitor = [
            "/tmp",
            os.path.join(home, ".config"),
            os.path.join(home, ".ssh"),
            home, # For .bashrc, etc. We will filter events later. Watchdog isn't great at non-recursive single files unless they exist, so we watch dir.
            "/etc/systemd/system",
            "/etc/cron.d"
        ]
        
        for path in paths_to_monitor:
            if os.path.exists(path):
                # Don't recurse on home directory to save CPU, just watch top level for .bashrc
                recursive = path != home
                try:
                    self.observer.schedule(self.handler, path, recursive=recursive)
                except PermissionError:
                    pass # We run as user, ignore restricted directories
                    
        self.observer.start()
        
    def collect_events(self) -> List[Dict[str, Any]]:
        events = []
        try:
            while True:
                events.append(self.event_queue.get_nowait())
        except queue.Empty:
            pass
        return events
        
    def stop(self):
        self.observer.stop()
        self.observer.join()
