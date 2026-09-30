import json
import os
import time
import psutil
from typing import Dict, Any
from security_guardian.ai.interface import AIAnalyzer

class LocalLLMAnalyzer(AIAnalyzer):
    def __init__(self, model_path: str = "models/Llama-3.2-1B-Instruct-Q4_K_M.gguf"):
        # We only import llama_cpp when needed so it doesn't crash if not installed
        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError("llama-cpp-python is not installed. Please install it to use LocalLLMAnalyzer.")
            
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}. Please run download_model.py first.")
            
        t0 = time.time()
        print("Loading local LLM...")
        self.llm = Llama(
            model_path=model_path,
            n_ctx=2048,
            verbose=False,
        )
        t1 = time.time()
        self.load_time = t1 - t0
        print(f"LLM loaded in {self.load_time:.2f}s")
        
        self.system_prompt = """You are a highly capable, objective AI cybersecurity analyst running locally.
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
            
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": prompt_content}
        ]
        
        process = psutil.Process()
        cpu_start = process.cpu_percent()
        mem_start = process.memory_info().rss
        t0 = time.time()
        
        try:
            response = self.llm.create_chat_completion(
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=512
            )
            
            t1 = time.time()
            cpu_end = process.cpu_percent()
            mem_end = process.memory_info().rss
            
            latency = t1 - t0
            completion_tokens = response.get("usage", {}).get("completion_tokens", 0)
            tokens_per_sec = completion_tokens / latency if latency > 0 else 0
            
            benchmarks = {
                "load_time_sec": self.load_time,
                "latency_sec": latency,
                "tokens_per_sec": tokens_per_sec,
                "cpu_percent": (cpu_start + cpu_end) / 2.0,
                "mem_mb": mem_end / (1024 * 1024)
            }
            
            output_text = response["choices"][0]["message"]["content"]
            
            try:
                result = json.loads(output_text)
                required_keys = {"severity", "confidence", "assessment", "evidence", "benign_explanation", "recommended_action"}
                if not required_keys.issubset(result.keys()):
                    raise ValueError(f"Missing keys. Required: {required_keys}")
                    
                result["benchmarks"] = benchmarks
                return result
                
            except (json.JSONDecodeError, ValueError) as e:
                if retry:
                    print(f"JSON Validation failed: {e}. Retrying...")
                    return self._run_inference_with_retry(incident, retry=False, correction_prompt=str(e))
                else:
                    raise e
                    
        except Exception as e:
            print(f"AI Analysis Error: {e}")
            return {
                "severity": "UNKNOWN",
                "confidence": 0.0,
                "assessment": f"Failed to run AI analysis: {str(e)}",
                "evidence": [],
                "benign_explanation": ["None"],
                "recommended_action": "INVESTIGATE",
                "benchmarks": {}
            }
