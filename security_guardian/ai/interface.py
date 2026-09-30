from abc import ABC, abstractmethod
from typing import Dict, Any

class AIAnalyzer(ABC):
    @abstractmethod
    def analyze(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes an incident and returns a structured JSON assessment.
        """
        pass
