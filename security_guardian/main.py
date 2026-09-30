import threading
import time
import queue
import psutil

from security_guardian.collectors.process_collector import ProcessCollector
from security_guardian.collectors.network_collector import NetworkCollector
from security_guardian.collectors.filesystem_collector import FilesystemCollector
from security_guardian.collectors.file_integrity_collector import FileIntegrityCollector
from security_guardian.collectors.persistence_collector import PersistenceCollector
from security_guardian.events.normalizer import EventNormalizer
from security_guardian.detection.correlator import EventCorrelator
from security_guardian.ui.dashboard import SecurityDashboard
from security_guardian.ai.local_llm import LocalLLMAnalyzer
from security_guardian.ai.npu_llm import QualcommNPUAnalyzer
import argparse

def ai_analysis_task(incident, data_queue, ai_analyzer):
    print(f"Running AI analysis for {incident.incident_id}...")
    
    # Sort events chronologically if timestamps are available
    sorted_events = sorted(incident.related_events, key=lambda e: getattr(e, "timestamp", ""))
    
    timeline = []
    for e in sorted_events:
        ts = getattr(e, "timestamp", "")
        # Format TS to just time if it's ISO, or keep as is
        if "T" in ts:
            ts = ts.split("T")[1].split(".")[0]
            
        event_str = f"[{ts}] {e.event_type}"
        if hasattr(e, "process"):
            event_str += f" | Process: {e.process}"
        if hasattr(e, "path"):
            event_str += f" | Path: {e.path}"
        if hasattr(e, "command_line") and e.command_line:
            event_str += f" | Cmd: {e.command_line}"
        if hasattr(e, "target"):
            event_str += f" | Target: {e.target}"
        if hasattr(e, "local_port"):
            event_str += f" | LocalPort: {e.local_port}"
        if hasattr(e, "remote_address"):
            event_str += f" | Remote: {e.remote_address}:{getattr(e, 'remote_port', '')}"
            
        timeline.append(event_str)

    # Prepare compact representation
    incident_data = {
        "incident_type": incident.rule_id,
        "severity_from_rules": incident.severity,
        "timeline": timeline
    }
    
    assessment = ai_analyzer.analyze(incident_data)
    incident.ai_assessment = assessment
    
    # Put updated incident back into the UI queue
    data_queue.put({
        "type": "incident_update",
        "data": incident
    })

def telemetry_loop(data_queue: queue.Queue, ai_backend: str):
    proc_col = ProcessCollector()
    net_col = NetworkCollector()
    fs_col = FilesystemCollector()
    integrity_col = FileIntegrityCollector()
    persistence_col = PersistenceCollector()
    normalizer = EventNormalizer()
    correlator = EventCorrelator()
    
    # Try to initialize AI
    ai_analyzer = None
    ai_metadata = None
    try:
        if ai_backend == "qualcomm_npu":
            ai_analyzer = QualcommNPUAnalyzer()
            ai_metadata = {
                "engine": "Qualcomm Snapdragon NPU",
                "model": "Qwen3-4B",
                "status": "● Local / NPU"
            }
        else:
            ai_analyzer = LocalLLMAnalyzer()
            ai_metadata = {
                "engine": "llama.cpp",
                "model": "Llama-3.2-1B-Instruct",
                "status": "● Local / CPU-GPU"
            }
        print(f"AI Analyzer ({ai_backend}) initialized successfully.")
    except Exception as e:
        print(f"AI Analyzer disabled: {e}")
    
    total_events = 0
    
    while True:
        try:
            # 1. Collect
            raw_procs = proc_col.collect_new_processes()
            raw_net = net_col.collect_new_activity()
            raw_fs = fs_col.collect_events()
            
            raw_integrity = integrity_col.process_raw_events(raw_fs)
            raw_persistence = persistence_col.process_raw_events(raw_fs)
            
            # 2. Normalize
            events = []
            if raw_procs:
                events.extend(normalizer.normalize_processes(raw_procs))
            if raw_net:
                events.extend(normalizer.normalize_network(raw_net))
            if raw_integrity:
                events.extend(normalizer.normalize_filesystem(raw_integrity))
            if raw_persistence:
                events.extend(normalizer.normalize_persistence(raw_persistence))
                
            total_events += len(events)
            
            # 3. Correlate and Detect
            incidents = correlator.add_events(events)
            
            # 4. Update UI
            # Send stats
            current_procs = len(proc_col.seen_pids)
            current_conns = len(net_col.seen_connections)
            
            data_queue.put({
                "type": "stats",
                "data": {
                    "processes": current_procs,
                    "connections": current_conns,
                    "events": total_events,
                    "ai_metadata": ai_metadata
                }
            })
            
            # Send incidents
            for inc in incidents:
                data_queue.put({
                    "type": "incident",
                    "data": inc
                })
                
                # Kick off AI analysis if available
                if ai_analyzer:
                    inc.ai_metadata = ai_metadata
                    threading.Thread(target=ai_analysis_task, args=(inc, data_queue, ai_analyzer), daemon=True).start()
                    
        except Exception as e:
            print(f"Error in telemetry loop: {e}")
            
        time.sleep(2) # Polling interval

def main():
    parser = argparse.ArgumentParser(description="Local Cyber Guardian")
    parser.add_argument("--ai-backend", choices=["local_llm", "qualcomm_npu"], default="local_llm", 
                        help="Choose the local AI backend (default: local_llm)")
    args = parser.parse_args()

    data_queue = queue.Queue()
    
    # Start telemetry in a background thread
    t = threading.Thread(target=telemetry_loop, args=(data_queue, args.ai_backend), daemon=True)
    t.start()
    
    # Start UI on the main thread
    app = SecurityDashboard(data_queue)
    app.mainloop()

if __name__ == "__main__":
    main()
