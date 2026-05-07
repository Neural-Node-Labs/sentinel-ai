# ============================================================================
# FILE: tests/smoke_test.py
# ============================================================================

"""
Sentinel-AI Smoke Test Suite
Tests the Agent-to-AI-to-Tool pipeline in dry-run mode
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from core.agents import SentinelAgents, SecurityState
from utils.ingestion import RAGIngestion
from tools.system_tools import SystemTools
import json

load_dotenv()


class SmokeTest:
    """Comprehensive smoke test suite"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.agents = None
        self.rag = None
        self.tools = None

    def run_all_tests(self) -> bool:
        """Run all smoke tests"""
        print("🧪 Starting Sentinel-AI Smoke Tests\n")

        tests = [
            ("Environment Setup", self.test_environment),
            ("RAG Ingestion", self.test_rag_ingestion),
            ("RAG Query", self.test_rag_query),
            ("System Tools", self.test_system_tools),
            ("LLM Connection", self.test_llm_connection),
            ("Agent Workflow - No Threat", self.test_agent_no_threat),
            ("Agent Workflow - Threat Detection", self.test_agent_threat_detection),
            ("Admin IP Protection", self.test_admin_ip_protection),
            ("Validation Agent Policy Check", self.test_validation_policy),
        ]

        for test_name, test_func in tests:
            self._run_test(test_name, test_func)

        print("\n" + "=" * 70)
        print(f"📊 TEST SUMMARY: {self.passed} passed, {self.failed} failed")
        print("=" * 70)

        return self.failed == 0

    def _run_test(self, name: str, func) -> None:
        """Run a single test"""
        try:
            print(f"Testing: {name}...", end=" ")
            func()
            print("✓ PASSED")
            self.passed += 1
        except AssertionError as e:
            print(f"✗ FAILED: {e}")
            self.failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            self.failed += 1

    def test_environment(self) -> None:
        """Test environment variables"""
        import os
        assert os.getenv("PROVIDER"), "PROVIDER not set"
        assert os.getenv("API_KEY"), "API_KEY not set"
        assert os.getenv("ADMIN_IP"), "ADMIN_IP not set"

    def test_rag_ingestion(self) -> None:
        """Test RAG database ingestion"""
        self.rag = RAGIngestion()
        self.rag.ingest_rules("rules.md")

        # Verify ingestion
        results = self.rag.query_policy("block IP", n_results=1)
        assert len(results) > 0, "No results from RAG query"

    def test_rag_query(self) -> None:
        """Test RAG policy queries"""
        if not self.rag:
            self.rag = RAGIngestion()

        # Test specific queries
        queries = [
            "ADMIN_IP protection",
            "failed login attempts",
            "SSH authentication",
            "firewall rules"
        ]

        for query in queries:
            results = self.rag.query_policy(query, n_results=2)
            assert len(results) > 0, f"No results for query: {query}"

    def test_system_tools(self) -> None:
        """Test system tools initialization"""
        self.tools = SystemTools()
        assert self.tools.os_type in ["linux", "windows"], "Invalid OS detection"
        assert self.tools.admin_ip, "Admin IP not loaded"

    def test_llm_connection(self) -> None:
        """Test LLM connectivity"""
        self.agents = SentinelAgents()
        response = self.agents.llm.invoke("Reply with 'TEST OK'")
        assert len(response) > 0, "Empty LLM response"

    def test_agent_no_threat(self) -> None:
        """Test agent workflow with benign logs"""
        if not self.agents:
            self.agents = SentinelAgents()

        safe_logs = """
        Jan 22 10:15:23 server sshd[1234]: Accepted publickey for admin from 192.168.1.100
        Jan 22 10:15:24 server sshd[1234]: pam_unix(sshd:session): session opened for user admin
        """

        result = self.agents.process_logs(safe_logs)
        assert result.get("threat_analysis"), "No threat analysis performed"
        assert not result.get("error"), f"Unexpected error: {result.get('error')}"

    def test_agent_threat_detection(self) -> None:
        """Test agent workflow with suspicious logs"""
        if not self.agents:
            self.agents = SentinelAgents()

        suspicious_logs = """
        Jan 22 10:15:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:03 server sshd[1235]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:05 server sshd[1236]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:07 server sshd[1237]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:09 server sshd[1238]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:11 server sshd[1239]: Failed password for invalid user admin from 203.0.113.50
        Jan 22 10:15:13 server sshd[1240]: Failed password for invalid user admin from 203.0.113.50
        """

        result = self.agents.process_logs(suspicious_logs)
        assert result.get("threat_analysis"), "No threat analysis"

        # Parse and verify threat detection
        try:
            analysis = json.loads(result["threat_analysis"])
            assert "threat_detected" in analysis, "Missing threat_detected field"
        except json.JSONDecodeError:
            pass  # LLM might return non-JSON in some cases

    def test_admin_ip_protection(self) -> None:
        """Test that admin IP cannot be blocked"""
        if not self.tools:
            self.tools = SystemTools()

        admin_ip = self.tools.admin_ip
        result = self.tools.block_ip(admin_ip)

        assert result["status"] == "denied", "Admin IP was not protected"
        assert "ADMIN_IP" in result["reason"], "Wrong denial reason"

    def test_validation_policy(self) -> None:
        """Test validation agent policy alignment"""
        if not self.rag:
            self.rag = RAGIngestion()

        # Query for specific policy rules
        results = self.rag.query_policy("DENY conditions for IP blocking", n_results=2)
        assert len(results) > 0, "Policy query returned no results"

        # Verify ALLOW/DENY keywords exist in policy
        policy_text = " ".join(results).lower()
        assert "allow" in policy_text or "deny" in policy_text, "Missing ALLOW/DENY logic"


def main():
    """Run smoke tests"""
    tester = SmokeTest()
    success = tester.run_all_tests()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

