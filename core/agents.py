# ============================================================================
# FILE: core/agents.py
# ============================================================================

from typing import TypedDict, Annotated, Literal
from langgraph.graph import StateGraph, END
from core.llm import LLMWrapper
from utils.ingestion import RAGIngestion
from tools.system_tools import SystemTools
import os
import json
from utils.logger_config import setup_logging
import logging
from dotenv import load_dotenv
load_dotenv()
# 1. Initialize the global configuration
setup_logging()
# 2. Get a logger for this specific file
logger = logging.getLogger(__name__)

class SecurityState(TypedDict):
    """State definition for the security agent workflow"""
    log_content: str
    threat_analysis: str
    validation_result: str
    action_plan: str
    execution_result: str
    hitl_approved: bool
    error: str | None


ActionType = Literal["allow", "deny", "block_ip", "alert"]


class SentinelAgents:
    """LangGraph-based security agent workflow"""

    def __init__(self):
        self.llm = LLMWrapper()
        self.rag = RAGIngestion()
        self.tools = SystemTools()
        self.hitl_mode = os.getenv("HITL", "False").lower() == "true"
        self.max_failed_attempts = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))

        # Build the graph
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine"""
        workflow = StateGraph(SecurityState)

        # Add nodes
        workflow.add_node("log_analysis", self._log_analysis_node)
        workflow.add_node("validation", self._validation_node)
        workflow.add_node("hitl_gate", self._hitl_gate_node)
        workflow.add_node("tool_execution", self._tool_execution_node)

        # Define edges
        workflow.set_entry_point("log_analysis")
        workflow.add_edge("log_analysis", "validation")

        # Conditional routing from validation
        workflow.add_conditional_edges(
            "validation",
            self._should_execute,
            {
                "execute": "hitl_gate",
                "deny": END,
                "error": END
            }
        )

        # HITL gate routing
        workflow.add_conditional_edges(
            "hitl_gate",
            self._hitl_decision,
            {
                "approved": "tool_execution",
                "denied": END
            }
        )

        workflow.add_edge("tool_execution", END)

        return workflow.compile()

    def _log_analysis_node(self, state: SecurityState) -> SecurityState:
        """Analyze security logs for threats"""
        prompt = f"""You are a security analyst. Analyze these authentication logs and identify potential threats:

{state['log_content']}

Focus on:
1. Failed authentication attempts from the same IP
2. Brute force patterns
3. Access to non-existent users
4. Suspicious timing or geographic patterns

Provide a JSON response with:
- threat_detected: bool
- threat_type: string
- source_ip: string (if applicable)
- severity: "critical" | "high" | "medium" | "low"
- evidence: string
- recommended_action: "block_ip" | "alert" | "monitor" | "none"

Response:"""

        try:
            response = self.llm.invoke(prompt)
            state["threat_analysis"] = response
            return state
        except Exception as e:
            state["error"] = f"Log analysis failed: {e}"
            return state

    def _validation_node(self, state: SecurityState) -> SecurityState:
        """Validate proposed actions against policy using RAG"""
        if state.get("error"):
            return state

        try:
            # Parse threat analysis
            analysis = json.loads(state["threat_analysis"])
            if not analysis.get("threat_detected"):
                state["validation_result"] = json.dumps({
                    "approved": False,
                    "reason": "No threat detected",
                    "action": "none"
                })
                return state

            # Query RAG for relevant policies
            query = (
                f"Policy for {analysis['threat_type']} from IP {analysis.get('source_ip', 'unknown')} "
                f"with severity {analysis['severity']}. Action: {analysis['recommended_action']}"
            )

            policy_context = self.rag.query_policy(query, n_results=3)
            logger.info(f"_validation_node.analysis: {analysis} , _validation_node.policy_context: {policy_context}")
            if not policy_context:
                # Safety Fail-Safe: Default to DENY if RAG unavailable
                state["validation_result"] = json.dumps({
                    "approved": False,
                    "reason": "RAG database unavailable - defaulting to DENY",
                    "action": "deny"
                })
                return state

            # Validate with LLM using policy context
            validation_prompt = f"""You are a security policy validator. Review this proposed action against our security policies.

THREAT ANALYSIS:
{json.dumps(analysis, indent=2)}

RELEVANT POLICIES:
{chr(10).join(policy_context)}

ADMIN_IP (must never be blocked): {self.tools.admin_ip}
MAX_FAILED_ATTEMPTS: {self.max_failed_attempts}

Determine if the action should be ALLOWED or DENIED based on policy.

Respond with JSON only:
{{
    "approved": true/false,
    "reason": "explanation",
    "action": "block_ip" | "alert" | "deny",
    "confidence": 0.0-1.0,
    "policy_matched": "specific policy rule"
}}

Response:"""

            validation_response = self.llm.invoke(validation_prompt)

            # Parse and validate
            validation_data = json.loads(validation_response)

            # Safety check: Never approve blocking admin IP
            if analysis.get("source_ip") == self.tools.admin_ip:
                validation_data["approved"] = False
                validation_data["reason"] = "Cannot take action against ADMIN_IP"

            state["validation_result"] = json.dumps(validation_data)
            return state

        except json.JSONDecodeError as e:
            state["error"] = f"JSON parsing error in validation: {e}"
            state["validation_result"] = json.dumps({
                "approved": False,
                "reason": f"Parsing error: {e}",
                "action": "deny"
            })
            return state
        except Exception as e:
            # Safety Fail-Safe
            state["error"] = f"Validation failed: {e}"
            state["validation_result"] = json.dumps({
                "approved": False,
                "reason": f"Validation error - defaulting to DENY: {e}",
                "action": "deny"
            })
            return state

    def _hitl_gate_node(self, state: SecurityState) -> SecurityState:
        """Human-in-the-Loop gate for approval"""
        if not self.hitl_mode:
            # Skip HITL, rely on Validation Agent
            state["hitl_approved"] = True
            return state

        # Display information for human review
        print("\n" + "=" * 70)
        print("🚨 HUMAN APPROVAL REQUIRED")
        print("=" * 70)
        print(f"\nTHREAT ANALYSIS:\n{state['threat_analysis']}")
        print(f"\nVALIDATION RESULT:\n{state['validation_result']}")
        print("\n" + "=" * 70)

        response = input("Approve this action? (yes/no): ").strip().lower()
        state["hitl_approved"] = response in ["yes", "y"]

        if not state["hitl_approved"]:
            print("❌ Action denied by human operator")
        else:
            print("✓ Action approved by human operator")

        return state

    def _tool_execution_node(self, state: SecurityState) -> SecurityState:
        """Execute approved security actions"""
        try:
            validation = json.loads(state["validation_result"])
            analysis = json.loads(state["threat_analysis"])

            action = validation.get("action", "deny")

            if action == "block_ip":
                source_ip = analysis.get("source_ip")
                if source_ip:
                    result = self.tools.block_ip(source_ip)
                    state["execution_result"] = json.dumps(result)
                else:
                    state["execution_result"] = json.dumps({
                        "status": "error",
                        "reason": "No source IP identified"
                    })

            elif action == "alert":
                state["execution_result"] = json.dumps({
                    "status": "success",
                    "action": "alert_sent",
                    "message": f"Alert: {validation['reason']}"
                })

            else:
                state["execution_result"] = json.dumps({
                    "status": "no_action",
                    "reason": validation.get("reason", "Action denied by policy")
                })

            return state

        except Exception as e:
            state["error"] = f"Execution failed: {e}"
            state["execution_result"] = json.dumps({
                "status": "error",
                "reason": str(e)
            })
            return state

    def _should_execute(self, state: SecurityState) -> Literal["execute", "deny", "error"]:
        """Determine if action should be executed"""
        if state.get("error"):
            return "error"

        try:
            validation = json.loads(state["validation_result"])
            return "execute" if validation.get("approved") else "deny"
        except:
            return "error"

    def _hitl_decision(self, state: SecurityState) -> Literal["approved", "denied"]:
        """Route based on HITL approval"""
        return "approved" if state.get("hitl_approved") else "denied"

    def process_logs(self, log_content: str) -> SecurityState:
        """
        Process security logs through the agent workflow.

        Args:
            log_content: Raw log content to analyze

        Returns:
            Final state after processing
        """
        initial_state: SecurityState = {
            "log_content": log_content,
            "threat_analysis": "",
            "validation_result": "",
            "action_plan": "",
            "execution_result": "",
            "hitl_approved": False,
            "error": None
        }

        final_state = self.graph.invoke(initial_state)
        return final_state

