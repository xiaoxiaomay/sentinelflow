"""
eval/garak_sentinelflow_adapter.py

garak Generator adapter: wraps SentinelFlow pipeline as a garak-compatible model.
garak sends attack prompts to this adapter and receives SentinelFlow's actual output.

Usage with garak CLI (v0.14+):
    garak --model_type function \
          --model_name eval.garak_sentinelflow_adapter.SentinelFlowGenerator \
          --probes encoding,dan
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("USE_POSTGRES", "false")

from garak.generators.base import Generator
from garak.attempt import Message


class SentinelFlowGenerator(Generator):
    """
    garak Generator adapter wrapping the SentinelFlow security gateway.
    Returns the post-firewall output (BLOCKED, REDACTED, or clean response).
    """

    name = "sentinelflow-gateway"
    generator_family_name = "SentinelFlow"
    supports_multiple_generations = False

    def __init__(self, name=None, config_root=None):
        # Lazy-load engine to avoid import cost until needed
        self._engine = None
        if name:
            self.name = name
        if config_root is None:
            from garak._config import GarakSubConfig
            config_root = GarakSubConfig()
        super().__init__(name=self.name, config_root=config_root)

    def _get_engine(self):
        if self._engine is None:
            from core.engine import SentinelEngine
            self._engine = SentinelEngine()
        return self._engine

    def generate(self, prompt, generations_this_call=1, typecheck=True):
        """
        Receive a garak Conversation/prompt, return list of Message responses.
        """
        # Extract text from garak's Conversation object
        if hasattr(prompt, "last_message"):
            query_text = prompt.last_message.text if prompt.last_message else ""
        elif isinstance(prompt, str):
            query_text = prompt
        else:
            query_text = str(prompt)

        try:
            engine = self._get_engine()
            result = engine.run_query(query_text)

            status = result.get("status", "")
            answer = result.get("answer", "")

            if "blocked" in status:
                response_text = f"[BLOCKED by {status}]"
            elif not answer:
                response_text = "[No response]"
            else:
                response_text = answer

        except Exception as e:
            response_text = f"[ERROR: {str(e)}]"

        return [Message(text=response_text)]
