"""
TMDD prompt generators.
"""
from .threat_prompt import generate_threat_model_prompt
from .agent_prompt import generate_agent_prompt

__all__ = ["generate_threat_model_prompt", "generate_agent_prompt"]

