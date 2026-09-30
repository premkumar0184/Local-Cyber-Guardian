import json
import time
import requests
from typing import Dict, Any
from security_guardian.ai.interface import AIAnalyzer

class QualcommNPUAnalyzer(AIAnalyzer):
    """
    Interfaces with Qualcomm's GenieAPIService running locally on Snapdragon Windows devices.
    Genie provides an OpenAI-compatible API on localhost:8910.
    """
    def __init__(self, model_name: str = "qwen3-4b"):
        self.model_name = model_name
        self.api_url = "http://localhost:8910/v1/chat/completions"
        self.load_time = 0.0 # Genie loads models ahead of time or on first request

        self.system_prompt = """You are a highly capable, objective AI cybersecurity analyst running locally on a Qualcomm NPU.
You monitor system telemetry and evaluate potential security incidents.
You receive a JSON object representing a compact incident timeline.

RULES:
1. You must only make claims supported by the supplied incident events.
2. You must distinguish between observed facts, suspicious indicators, and possible benign explanations.
3. You must never automatically claim an event is malware. Always acknowledge legitimate use cases.
4. You must analyze the behavior and return a strict JSON object with your assessment.
Do not output markdown, do not output explanations outside of the JSON.

Your JSON must exactly match this schema:
{
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": <float between 0.0 and 1.0>,
  "assessment": "<String summarizing your objective finding>",
  "evidence": ["<observed fact 1>", "<suspicious indicator 2>"],
  "benign_explanation": ["<possible legitimate reason 1>", "<possible legitimate reason 2>"],
  "recommended_action": "INVESTIGATE" | "MONITOR" | "TERMINATE"
}
"""

    def analyze(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return self._run_inference_with_retry(incident, retry=True)

    def _run_inference_with_retry(self, incident: Dict[str, Any], retry: bool = True, correction_prompt: str = "") -> Dict[str, Any]:
        prompt_content = json.dumps(incident, indent=2)
        if correction_prompt:
            prompt_content += f"\n\nERROR IN PREVIOUS OUTPUT:\n{correction_prompt}\nPlease provide VALID JSON matching the schema."
            
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt_content}
            ],
            "temperature": 0.1,
            # Genie/OpenAI compatible flag for forcing JSON
            "response_format": {"type": "json_object"}
        }

        t0 = time.time()
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            t1 = time.time()
            latency = t1 - t0
            
            completion_tokens = data.get("usage", {}).get("completion_tokens", 0)
            tokens_per_sec = completion_tokens / latency if latency > 0 else 0
            
            benchmarks = {
                "load_time_sec": self.load_time,
                "latency_sec": latency,
                "tokens_per_sec": tokens_per_sec,
                # Process metrics are handled by Genie, so we omit host CPU/RAM here
                "cpu_percent": 0.0, 
                "mem_mb": 0.0
            }
            
            output_text = data["choices"][0]["message"]["content"]
            
            try:
                result = json.loads(output_text)
                required_keys = {"severity", "confidence", "assessment", "evidence", "benign_explanation", "recommended_action"}
                if not required_keys.issubset(result.keys()):
                    raise ValueError(f"Missing keys. Required: {required_keys}")
                    
                result["benchmarks"] = benchmarks
                return result
                
            except (json.JSONDecodeError, ValueError) as e:
                if retry:
                    print(f"[NPU] JSON Validation failed: {e}. Retrying...")
                    return self._run_inference_with_retry(incident, retry=False, correction_prompt=str(e))
                else:
                    raise e
                    
        except requests.exceptions.ConnectionError:
            print("[NPU] ERROR: Could not connect to GenieAPIService on localhost:8910. Is it running?")
            return self._fallback_error("GenieAPIService is offline or unreachable.")
        except requests.exceptions.Timeout:
            print("[NPU] ERROR: GenieAPIService inference timed out.")
            return self._fallback_error("NPU Inference timed out.")
        except Exception as e:
            print(f"[NPU] AI Analysis Error: {e}")
            return self._fallback_error(str(e))

    def _fallback_error(self, message: str) -> Dict[str, Any]:
        return {
            "severity": "UNKNOWN",
            "confidence": 0.0,
            "assessment": f"Failed to run AI analysis: {message}",
            "evidence": [],
            "benign_explanation": ["None"],
            "recommended_action": "INVESTIGATE",
            "benchmarks": {}
        }
