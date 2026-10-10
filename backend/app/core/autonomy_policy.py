from enum import Enum
from app.core.scope_gate import HIGH_RISK_TOOLS

class AutonomyLevel(str, Enum):
    SUGGEST_ONLY = "suggest_only"
    HUMAN_GATED = "human_gated"
    AUTONOMOUS = "autonomous"

def evaluate_execution_policy(autonomy_level: str, tool_name: str, action_type: str, risk_level: str) -> dict:
    """
    Determines if an action can run immediately or requires manual operator sign-off.
    Returns: {"can_execute": bool, "requires_approval": bool, "status": str}
    """
    tool_normalized = tool_name.lower().strip()
    
    # 1. Non-bypassable fail-safe: High-risk tools always require manual approval
    if tool_normalized in HIGH_RISK_TOOLS:
        return {
            "can_execute": False,
            "requires_approval": True,
            "status": "awaiting_approval",
            "reason": f"Tool '{tool_name}' belongs to HIGH_RISK_TOOLS registry."
        }

    # 2. Suggest Only: AI formulates plans, never executes
    if autonomy_level == AutonomyLevel.SUGGEST_ONLY:
        return {
            "can_execute": False,
            "requires_approval": True,
            "status": "proposed",
            "reason": "Engagement set to suggest_only; manual trigger required."
        }

    # 3. Human Gated (Default): Recon auto-executes; intrusive tools require approval
    if autonomy_level == AutonomyLevel.HUMAN_GATED:
        if action_type == "scan" and risk_level.lower() in ("low", "info"):
            return {
                "can_execute": True,
                "requires_approval": False,
                "status": "approved",
                "reason": "Reconnaissance tool auto-approved under human_gated policy."
            }
        return {
            "can_execute": False,
            "requires_approval": True,
            "status": "awaiting_approval",
            "reason": "Action type or risk level requires human verification."
        }

    # 4. Autonomous: Everything runs automatically except HIGH_RISK_TOOLS
    if autonomy_level == AutonomyLevel.AUTONOMOUS:
        return {
            "can_execute": True,
            "requires_approval": False,
            "status": "approved",
            "reason": "Auto-executed under autonomous engagement policy."
        }

    # Default fallback to safest gate
    return {
        "can_execute": False,
        "requires_approval": True,
        "status": "awaiting_approval",
        "reason": "Unknown autonomy mode. Gated by default."
    }