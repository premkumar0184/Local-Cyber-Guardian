import psutil
from typing import List, Dict, Any

class ProcessCollector:
    def __init__(self):
        self.seen_pids = set()
        # Initialize with currently running processes to avoid a massive spike on startup
        for p in psutil.process_iter(['pid']):
            self.seen_pids.add(p.info['pid'])

    def collect_new_processes(self) -> List[Dict[str, Any]]:
        new_processes = []
        current_pids = set()
        
        for p in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'cmdline', 'create_time']):
            try:
                pid = p.info['pid']
                current_pids.add(pid)
                
                if pid not in self.seen_pids:
                    # New process found
                    self.seen_pids.add(pid)
                    
                    # Try to get parent process name safely
                    parent_name = "unknown"
                    ppid = p.info['ppid']
                    if ppid:
                        try:
                            parent_process = psutil.Process(ppid)
                            parent_name = parent_process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass

                    new_processes.append({
                        'pid': pid,
                        'name': p.info['name'] or 'unknown',
                        'exe': p.info['exe'] or 'unknown',
                        'ppid': ppid,
                        'parent_name': parent_name,
                        'username': p.info['username'],
                        'cmdline': p.info['cmdline'],
                        'create_time': p.info['create_time']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        # Clean up seen_pids for processes that have terminated
        self.seen_pids.intersection_update(current_pids)
        
        return new_processes
