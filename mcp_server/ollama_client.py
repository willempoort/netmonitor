"""
Ollama Client for NetMonitor MCP Server

Provides integration with local Ollama instance for AI-powered threat analysis
"""

import logging
import json
from typing import Dict, Optional, List
import requests


logger = logging.getLogger('NetMonitor.Ollama')


class OllamaClient:
    """Client for communicating with local Ollama instance"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        """
        Initialize Ollama client

        Args:
            base_url: Ollama API base URL (default: http://localhost:11434)
            model: Model to use for inference (default: llama3.2)
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.available = False

        # Check if Ollama is available
        self._check_availability()

    def _check_availability(self) -> bool:
        """Check if Ollama is available and responding"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            if response.status_code == 200:
                self.available = True
                models = response.json().get('models', [])
                logger.info(f"Ollama is available with {len(models)} models")

                # Check if our preferred model is available
                model_names = [m.get('name', '') for m in models]
                if not any(self.model in name for name in model_names):
                    logger.warning(f"Preferred model '{self.model}' not found. Available: {model_names}")

                return True
            else:
                logger.warning(f"Ollama returned status {response.status_code}")
                return False
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self.available = False
            return False

    def generate(self, prompt: str, system: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Dict:
        """
        Generate completion using Ollama

        Args:
            prompt: User prompt
            system: System prompt (optional)
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate

        Returns:
            Response dictionary with 'response' and 'model' keys
        """
        if not self.available:
            raise Exception("Ollama is not available. Check if Ollama is running: ollama serve")

        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }

            if system:
                payload["system"] = system

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=60  # Ollama can take time for larger models
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"Generated response using {self.model}")
                return {
                    "response": result.get("response", ""),
                    "model": result.get("model", self.model),
                    "success": True
                }
            else:
                logger.error(f"Ollama error: {response.status_code} - {response.text}")
                return {
                    "response": f"Error: Ollama returned status {response.status_code}",
                    "success": False,
                    "error": response.text
                }

        except requests.exceptions.Timeout:
            logger.error("Ollama request timed out")
            return {
                "response": "Error: Request timed out (Ollama may be processing, try again)",
                "success": False,
                "error": "timeout"
            }
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return {
                "response": f"Error: {str(e)}",
                "success": False,
                "error": str(e)
            }

    def analyze_threat(self, alert: Dict) -> Dict:
        """
        Analyze a security threat using Ollama

        Args:
            alert: Alert dictionary with threat details

        Returns:
            Analysis results
        """
        system_prompt = """You are a cybersecurity expert analyzing network security threats.
Provide detailed analysis including:
1. Threat assessment (severity and risk)
2. Potential attack vector and tactics
3. Recommended immediate actions
4. Investigation steps
5. Indicators to monitor

Be concise but thorough. Use bullet points."""

        user_prompt = f"""Analyze this security alert:

Threat Type: {alert.get('threat_type', 'Unknown')}
Severity: {alert.get('severity', 'Unknown')}
Source IP: {alert.get('source_ip', 'Unknown')}
Destination IP: {alert.get('destination_ip', 'Unknown')}
Description: {alert.get('description', 'No description')}
Timestamp: {alert.get('timestamp', 'Unknown')}

Additional Context:
{json.dumps(alert.get('metadata', {}), indent=2) if alert.get('metadata') else 'None'}

Provide your security analysis:"""

        result = self.generate(user_prompt, system=system_prompt, temperature=0.3)

        return {
            "alert_id": alert.get('id'),
            "threat_type": alert.get('threat_type'),
            "analysis": result.get("response", ""),
            "model": result.get("model"),
            "success": result.get("success", False)
        }

    def suggest_incident_response(self, alert: Dict, context: Optional[str] = None) -> Dict:
        """
        Generate incident response recommendations

        Args:
            alert: Alert dictionary
            context: Additional context (optional)

        Returns:
            Incident response suggestions
        """
        system_prompt = """You are a cybersecurity incident responder.
Provide actionable incident response recommendations following the NIST framework:
1. Preparation
2. Detection & Analysis
3. Containment
4. Eradication
5. Recovery
6. Post-Incident Activity

Be specific and actionable. Prioritize by urgency."""

        user_prompt = f"""Generate incident response plan for:

Threat: {alert.get('threat_type', 'Unknown')}
Severity: {alert.get('severity', 'Unknown')}
Source: {alert.get('source_ip', 'Unknown')}
Target: {alert.get('destination_ip', 'Unknown')}
Details: {alert.get('description', 'Unknown')}

{f"Additional Context: {context}" if context else ""}

Provide step-by-step incident response:"""

        result = self.generate(user_prompt, system=system_prompt, temperature=0.4)

        return {
            "alert_id": alert.get('id'),
            "severity": alert.get('severity'),
            "response_plan": result.get("response", ""),
            "model": result.get("model"),
            "success": result.get("success", False)
        }

    def explain_ioc(self, ioc: str, ioc_type: str = "ip") -> Dict:
        """
        Explain an Indicator of Compromise (IOC) in simple terms

        Args:
            ioc: The IOC value (IP, domain, hash, etc.)
            ioc_type: Type of IOC (ip, domain, hash, url)

        Returns:
            Explanation of the IOC
        """
        system_prompt = """You are a cybersecurity educator explaining threats to non-technical people.
Explain the indicator of compromise in simple, clear language that anyone can understand.
Include:
1. What this indicator represents
2. Why it's considered suspicious/malicious
3. What it typically indicates
4. Real-world context and examples

Avoid jargon. Use analogies if helpful."""

        user_prompt = f"""Explain this security indicator in simple terms:

Type: {ioc_type.upper()}
Value: {ioc}

Explain what this means and why it matters:"""

        result = self.generate(user_prompt, system=system_prompt, temperature=0.5)

        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "explanation": result.get("response", ""),
            "model": result.get("model"),
            "success": result.get("success", False)
        }

    def list_available_models(self) -> List[Dict]:
        """
        List available Ollama models

        Returns:
            List of available models
        """
        if not self.available:
            return []

        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                return response.json().get('models', [])
            return []
        except Exception as e:
            logger.error(f"Error listing models: {e}")
            return []

    def get_status(self) -> Dict:
        """
        Get Ollama status

        Returns:
            Status dictionary
        """
        models = self.list_available_models()

        return {
            "available": self.available,
            "base_url": self.base_url,
            "current_model": self.model,
            "models_available": len(models),
            "models": [m.get('name', 'unknown') for m in models]
        }
