import customtkinter as ctk
import queue
import tkinter.messagebox as messagebox
import subprocess
import psutil
from typing import Dict, Any

class SecurityDashboard(ctk.CTk):
    def __init__(self, data_queue: queue.Queue):
        super().__init__()
        
        self.data_queue = data_queue
        
        # Modern aesthetics
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.title("Local AI Endpoint Security Guardian")
        self.geometry("900x700")
        
        # Layout config
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)
        
        # Header (Top row across both columns)
        self.header_frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0)
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        self.header_label = ctk.CTkLabel(self.header_frame, text="🛡️ SECURITY GUARDIAN", font=ctk.CTkFont(family="Inter", size=24, weight="bold"))
        self.header_label.pack(side="left", padx=20, pady=15)
        
        self.badge_frame = ctk.CTkFrame(self.header_frame, fg_color="#16213e", corner_radius=15)
        self.badge_frame.pack(side="right", padx=20, pady=15)
        self.badge_label = ctk.CTkLabel(self.badge_frame, text="LOCAL AI: SECURE & OFFLINE", text_color="#00ffcc", font=ctk.CTkFont(size=12, weight="bold"))
        self.badge_label.pack(padx=10, pady=5)
        
        # Left Column: Status & Timeline
        self.left_col = ctk.CTkFrame(self, fg_color="transparent")
        self.left_col.grid(row=1, column=0, padx=(20, 10), pady=20, sticky="nsew")
        self.left_col.grid_rowconfigure(1, weight=1)
        
        # Stats Card
        self.stats_card = ctk.CTkFrame(self.left_col, fg_color="#0f3460", corner_radius=10)
        self.stats_card.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        ctk.CTkLabel(self.stats_card, text="DEVICE STATUS", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        self.proc_label = ctk.CTkLabel(self.stats_card, text="Processes: 0")
        self.proc_label.pack(anchor="w", padx=20, pady=2)
        self.conn_label = ctk.CTkLabel(self.stats_card, text="Connections: 0")
        self.conn_label.pack(anchor="w", padx=20, pady=2)
        self.event_label = ctk.CTkLabel(self.stats_card, text="Recent events: 0")
        self.event_label.pack(anchor="w", padx=20, pady=(2, 15))
        
        # AI Backend Card
        self.backend_card = ctk.CTkFrame(self.left_col, fg_color="#1a1a2e", corner_radius=10)
        self.backend_card.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        ctk.CTkLabel(self.backend_card, text="AI BACKEND", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        self.engine_label = ctk.CTkLabel(self.backend_card, text="ENGINE: -")
        self.engine_label.pack(anchor="w", padx=20, pady=2)
        self.model_label = ctk.CTkLabel(self.backend_card, text="MODEL: -")
        self.model_label.pack(anchor="w", padx=20, pady=2)
        self.status_backend_label = ctk.CTkLabel(self.backend_card, text="STATUS: -", text_color="#00ffcc")
        self.status_backend_label.pack(anchor="w", padx=20, pady=(2, 15))
        
        # Timeline Card
        self.timeline_card = ctk.CTkFrame(self.left_col, corner_radius=10)
        self.timeline_card.grid(row=2, column=0, sticky="nsew")
        ctk.CTkLabel(self.timeline_card, text="INCIDENT TIMELINE", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(15, 5))
        self.timeline_text = ctk.CTkTextbox(self.timeline_card, fg_color="#1a1a2e", text_color="#a9a9b3")
        self.timeline_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.timeline_text.configure(state="disabled")
        
        # Right Column: AI Assessment
        self.right_col = ctk.CTkFrame(self, fg_color="transparent")
        self.right_col.grid(row=1, column=1, padx=(10, 20), pady=20, sticky="nsew")
        self.right_col.grid_rowconfigure(0, weight=1)
        
        self.ai_card = ctk.CTkFrame(self.right_col, corner_radius=10)
        self.ai_card.grid(row=0, column=0, sticky="nsew")
        
        self.ai_header = ctk.CTkFrame(self.ai_card, fg_color="transparent")
        self.ai_header.pack(fill="x", padx=20, pady=20)
        self.incident_title = ctk.CTkLabel(self.ai_header, text="No active incidents", font=ctk.CTkFont(size=20, weight="bold"), text_color="gray")
        self.incident_title.pack(side="left")
        self.confidence_label = ctk.CTkLabel(self.ai_header, text="", font=ctk.CTkFont(size=14))
        self.confidence_label.pack(side="right")
        
        self.assessment_label = ctk.CTkLabel(self.ai_card, text="", font=ctk.CTkFont(size=14, slant="italic"), wraplength=400, justify="left")
        self.assessment_label.pack(anchor="w", padx=20, pady=(0, 20))
        
        self.ai_details = ctk.CTkTextbox(self.ai_card, fg_color="#1a1a2e", font=ctk.CTkFont(size=13))
        self.ai_details.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.ai_details.configure(state="disabled")
        
        # Benchmarks
        self.benchmark_label = ctk.CTkLabel(self.ai_card, text="", font=ctk.CTkFont(size=11), text_color="gray")
        self.benchmark_label.pack(anchor="e", padx=20, pady=(0, 10))
        
        # Actions
        self.action_frame = ctk.CTkFrame(self.ai_card, fg_color="transparent")
        self.action_frame.pack(fill="x", padx=20, pady=20)
        
        self.current_incident = None
        self.btn_investigate = ctk.CTkButton(self.action_frame, text="Investigate", state="disabled", command=self.on_investigate)
        self.btn_investigate.pack(side="left", padx=5)
        self.btn_view = ctk.CTkButton(self.action_frame, text="View Process", state="disabled", command=self.on_view_process)
        self.btn_view.pack(side="left", padx=5)
        self.btn_terminate = ctk.CTkButton(self.action_frame, text="Terminate", state="disabled", fg_color="#e94560", hover_color="#c81d39", command=self.on_terminate)
        self.btn_terminate.pack(side="right", padx=5)
        
        # Start check loop
        self.after(500, self.process_queue)
        
    def process_queue(self):
        try:
            while True:
                data = self.data_queue.get_nowait()
                if data["type"] == "stats":
                    self.update_stats(data["data"])
                elif data["type"] == "incident" or data["type"] == "incident_update":
                    self.update_incident(data["data"])
        except queue.Empty:
            pass
        finally:
            self.after(500, self.process_queue)
            
    def update_stats(self, stats: Dict[str, Any]):
        self.proc_label.configure(text=f"Processes: {stats.get('processes', 0)}")
        self.conn_label.configure(text=f"Connections: {stats.get('connections', 0)}")
        self.event_label.configure(text=f"Recent events: {stats.get('events', 0)}")
        
        if "ai_metadata" in stats and stats["ai_metadata"]:
            meta = stats["ai_metadata"]
            self.engine_label.configure(text=f"ENGINE: {meta.get('engine', '')}")
            self.model_label.configure(text=f"MODEL: {meta.get('model', '')}")
            self.status_backend_label.configure(text=f"STATUS: {meta.get('status', '')}")
        
    def update_incident(self, incident: Any):
        self.current_incident = incident
        
        # 1. Title and Severity
        severity = incident.severity
        color = "#e94560" if severity in ["HIGH", "CRITICAL"] else "#f8b400"
        if hasattr(incident, "ai_assessment") and incident.ai_assessment and "severity" in incident.ai_assessment:
            severity = str(incident.ai_assessment.get("severity", severity)).upper()
            color = "#e94560" if severity in ["HIGH", "CRITICAL"] else "#f8b400"
            if severity == "LOW": color = "#00ffcc"
            
        self.incident_title.configure(text=f"{severity} RISK: {incident.process_name}", text_color=color)
        
        # 2. Timeline
        self.timeline_text.configure(state="normal")
        self.timeline_text.delete("1.0", "end")
        
        timeline_events = []
        # Recreate timeline for display (similar to what was sent to LLM)
        sorted_events = sorted(incident.related_events, key=lambda e: getattr(e, "timestamp", ""))
        for e in sorted_events:
            ts = getattr(e, "timestamp", "")
            if "T" in ts: ts = ts.split("T")[1].split(".")[0]
            t_str = f"[{ts}] {e.event_type}\n"
            if hasattr(e, "path"): t_str += f"   └─ {e.path}\n"
            elif hasattr(e, "target"): t_str += f"   └─ {e.target}\n"
            elif hasattr(e, "local_port"): t_str += f"   └─ Port {e.local_port}\n"
            timeline_events.append(t_str)
            
        if not timeline_events:
            self.timeline_text.insert("1.0", "Deterministic reasons:\n" + "\n".join(incident.reason.split(" + ")))
        else:
            self.timeline_text.insert("1.0", "\n".join(timeline_events))
            
        self.timeline_text.configure(state="disabled")
        
        # 3. AI Assessment Details
        self.ai_details.configure(state="normal")
        self.ai_details.delete("1.0", "end")
        
        if hasattr(incident, "ai_assessment") and incident.ai_assessment:
            ai = incident.ai_assessment
            conf = int(ai.get("confidence", 0) * 100)
            self.confidence_label.configure(text=f"{conf}% Confidence", text_color="#00ffcc")
            self.assessment_label.configure(text=f'"{ai.get("assessment", "")}"')
            
            details = "🔎 WHY THIS WAS FLAGGED:\n\n"
            for ev in ai.get("evidence", []):
                details += f"  • {ev}\n"
                
            details += "\n✅ POSSIBLE BENIGN EXPLANATION:\n\n"
            benign = ai.get("benign_explanation", [])
            for b in benign:
                details += f"  • {b}\n"
                
            details += f"\n👉 RECOMMENDED ACTION: {ai.get('recommended_action', 'INVESTIGATE')}\n"
            
            self.ai_details.insert("1.0", details)
            
            # Benchmarks
            bench = ai.get("benchmarks", {})
            if bench:
                bench_str = f"Load: {bench.get('load_time_sec',0):.1f}s | Latency: {bench.get('latency_sec',0):.1f}s | Speed: {bench.get('tokens_per_sec',0):.1f} t/s | CPU: {bench.get('cpu_percent',0):.1f}% | Mem: {bench.get('mem_mb',0):.0f}MB"
                self.benchmark_label.configure(text=bench_str)
                
        else:
            self.confidence_label.configure(text="Analyzing...")
            self.assessment_label.configure(text="Local AI is currently analyzing this behavior...")
            self.ai_details.insert("1.0", "\n\nPlease wait while the offline local LLM processes the timeline.\nThis usually takes 2-5 seconds depending on hardware.")
            self.benchmark_label.configure(text="")
            
        self.ai_details.configure(state="disabled")
        
        # 4. Action Buttons
        self.btn_investigate.configure(state="normal")
        self.btn_view.configure(state="normal")
        if incident.pid and incident.pid != -1:
            self.btn_terminate.configure(state="normal")
        else:
            self.btn_terminate.configure(state="disabled")

    def on_investigate(self):
        if not self.current_incident: return
        messagebox.showinfo("Investigate", f"Reviewing logs for incident {self.current_incident.incident_id}...")

    def on_view_process(self):
        if not self.current_incident: return
        pid = self.current_incident.pid
        if pid and pid != -1:
            try:
                subprocess.Popen(["gnome-terminal", "--", "top", "-p", str(pid)])
            except Exception:
                messagebox.showinfo("Process Info", f"Process ID: {pid}\nName: {self.current_incident.process_name}")
        else:
            messagebox.showwarning("Warning", "No valid PID associated with this incident.")

    def on_terminate(self):
        if not self.current_incident: return
        pid = self.current_incident.pid
        if not pid or pid == -1: return
        
        confirm = messagebox.askyesno("Confirm Termination", f"Are you sure you want to terminate process {self.current_incident.process_name} (PID: {pid})?")
        if confirm:
            try:
                p = psutil.Process(pid)
                p.terminate()
                messagebox.showinfo("Terminated", f"Process {pid} terminated successfully.")
                self.btn_terminate.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process: {e}")
