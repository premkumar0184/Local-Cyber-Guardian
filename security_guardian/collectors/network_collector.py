import psutil
from typing import List, Dict, Any

class NetworkCollector:
    def __init__(self):
        self.seen_connections = set()
        # Initialize with current connections
        for conn in psutil.net_connections(kind='inet'):
            conn_id = self._get_conn_id(conn)
            if conn_id:
                self.seen_connections.add(conn_id)

    def _get_conn_id(self, conn) -> str:
        # Create a unique identifier for a connection to track if it's new
        if not conn.laddr:
            return None
        
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "none"
        
        return f"{conn.pid}-{conn.status}-{laddr}-{raddr}"

    def collect_new_activity(self) -> List[Dict[str, Any]]:
        new_activity = []
        current_connections = set()
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_id = self._get_conn_id(conn)
                if not conn_id:
                    continue
                    
                current_connections.add(conn_id)
                
                if conn_id not in self.seen_connections:
                    self.seen_connections.add(conn_id)
                    
                    # Try to get process name
                    process_name = "unknown"
                    if conn.pid:
                        try:
                            p = psutil.Process(conn.pid)
                            process_name = p.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass

                    activity = {
                        'pid': conn.pid,
                        'process_name': process_name,
                        'status': conn.status,
                        'laddr': conn.laddr.ip if conn.laddr else None,
                        'lport': conn.laddr.port if conn.laddr else None,
                        'raddr': conn.raddr.ip if conn.raddr else None,
                        'rport': conn.raddr.port if conn.raddr else None,
                    }
                    
                    # We are particularly interested in new LISTEN sockets and new ESTABLISHED outbound connections
                    if conn.status == 'LISTEN':
                        activity['activity_type'] = 'LISTEN'
                        new_activity.append(activity)
                    elif conn.status == 'ESTABLISHED' and conn.raddr:
                        # Simple heuristic: if remote port is typical outbound (80, 443, etc) or just track all established
                        activity['activity_type'] = 'OUTBOUND'
                        new_activity.append(activity)

        except psutil.AccessDenied:
            # Need to run as root to get all connections, otherwise we only get our user's
            pass
            
        # Clean up old connections
        self.seen_connections.intersection_update(current_connections)
        
        return new_activity
