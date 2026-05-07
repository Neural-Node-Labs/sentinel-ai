# ============================================================================
# FILE: main.py
# ============================================================================

import time
from pathlib import Path
from dotenv import load_dotenv
from utils.ingestion import RAGIngestion
from core.agents import SentinelAgents
from tools.system_tools import SystemTools
import os
import json


class SentinelAI:
    """Main orchestrator for Sentinel-AI security system"""

    def __init__(self):
        self.verify_environment()
        self.rag = RAGIngestion()
        self.agents = SentinelAgents()
        self.tools = SystemTools()
        self.running = False

    @staticmethod
    def verify_environment() -> None:
        """Verify all required environment variables and files"""
        print("🔍 Verifying Sentinel-AI environment...")

        # Check .env file
        if not Path(".env").exists():
            raise FileNotFoundError("Missing .env file")

        load_dotenv()

        # Check required env vars
        required_vars = ["PROVIDER", "API_KEY", "ADMIN_IP"]
        missing = [var for var in required_vars if not os.getenv(var)]

        if missing:
            raise EnvironmentError(f"Missing required environment variables: {missing}")

        # Check rules.md
        if not Path("rules.md").exists():
            raise FileNotFoundError("Missing rules.md policy file")

        # Validate ADMIN_IP format
        admin_ip = os.getenv("ADMIN_IP", "")
        if not SystemTools._validate_ip(admin_ip):
            raise ValueError(f"Invalid ADMIN_IP format: {admin_ip}")

        print("✓ Environment verification complete")

    def initialize(self) -> None:
        """Initialize the system (ingest policies, verify connections)"""
        print("\n🚀 Initializing Sentinel-AI...")

        # Ingest security policies
        print("📚 Ingesting security policies into RAG database...")
        self.rag.ingest_rules("rules.md")

        # Test LLM connection
        print(f"🤖 Testing LLM connection ({self.agents.llm.provider})...")
        try:
            response = self.agents.llm.invoke("Respond with 'OK' if you receive this.")
            print(f"✓ LLM connection successful: {response[:50]}")
        except Exception as e:
            raise RuntimeError(f"LLM connection failed: {e}")

        # Display configuration
        provider_info = self.agents.llm.get_provider_info()
        print("\n📋 Configuration:")
        print(f"  - Provider: {provider_info['provider']}")
        print(f"  - Model: {provider_info['model']}")
        print(f"  - Temperature: {provider_info['temperature']}")
        print(f"  - HITL Mode: {self.agents.hitl_mode}")
        print(f"  - Admin IP: {self.tools.admin_ip}")
        print(f"  - OS Type: {self.tools.os_type}")

        print("\n✓ Sentinel-AI initialized successfully")

    def analyze_current_logs(self) -> None:
        """Analyze current system logs"""
        print("\n🔎 Analyzing recent authentication logs...")

        # Retrieve logs
        log_content = self.tools.get_recent_logs(num_lines=50)

        if not log_content or "Error" in log_content:
            print(f"⚠️  Could not retrieve logs: {log_content}")
            return

        print(f"✓ Retrieved {len(log_content.splitlines())} log lines")

        # Process through agent workflow
        print("\n🤖 Processing logs through AI agent workflow...")
        result = self.agents.process_logs(log_content)

        # Display results
        self._display_results(result)

    def start_monitoring(self, interval: int = 60) -> None:
        """
        Start continuous log monitoring.

        Args:
            interval: Seconds between checks
        """
        print(f"\n👁️  Starting continuous monitoring (interval: {interval}s)")
        print("Press Ctrl+C to stop\n")

        self.running = True

        try:
            while self.running:
                self.analyze_current_logs()
                print(f"\n⏳ Waiting {interval} seconds until next check...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped by user")
            self.running = False

    @staticmethod
    def _display_results(state: dict) -> None:
        """Display analysis results in formatted output"""
        print("\n" + "=" * 70)
        print("📊 ANALYSIS RESULTS")
        print("=" * 70)

        if state.get("error"):
            print(f"\n❌ ERROR: {state['error']}")
            return

        # Threat Analysis
        if state.get("threat_analysis"):
            print("\n🔍 THREAT ANALYSIS:")
            try:
                analysis = json.loads(state["threat_analysis"])
                print(f"  Threat Detected: {analysis.get('threat_detected')}")
                if analysis.get('threat_detected'):
                    print(f"  Type: {analysis.get('threat_type')}")
                    print(f"  Source IP: {analysis.get('source_ip')}")
                    print(f"  Severity: {analysis.get('severity')}")
                    print(f"  Evidence: {analysis.get('evidence')}")
                    print(f"  Recommended: {analysis.get('recommended_action')}")
            except json.JSONDecodeError:
                print(f"  {state['threat_analysis'][:200]}")

        # Validation Result
        if state.get("validation_result"):
            print("\n✅ VALIDATION RESULT:")
            try:
                validation = json.loads(state["validation_result"])
                print(f"  Approved: {validation.get('approved')}")
                print(f"  Reason: {validation.get('reason')}")
                print(f"  Action: {validation.get('action')}")
                if validation.get('policy_matched'):
                    print(f"  Policy: {validation.get('policy_matched')}")
            except json.JSONDecodeError:
                print(f"  {state['validation_result'][:200]}")

        # Execution Result
        if state.get("execution_result"):
            print("\n⚙️  EXECUTION RESULT:")
            try:
                execution = json.loads(state["execution_result"])
                print(f"  Status: {execution.get('status')}")
                if execution.get('action'):
                    print(f"  Action Taken: {execution.get('action')}")
                if execution.get('ip'):
                    print(f"  Target IP: {execution.get('ip')}")
                if execution.get('reason'):
                    print(f"  Reason: {execution.get('reason')}")
            except json.JSONDecodeError:
                print(f"  {state['execution_result'][:200]}")

        print("\n" + "=" * 70 + "\n")


def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                        SENTINEL-AI v1.0                           ║
║            Autonomous Server Security Active Protection           ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    try:
        sentinel = SentinelAI()
        sentinel.initialize()

        print("\n" + "=" * 70)
        print("OPTIONS:")
        print("  1. Analyze current logs (one-time)")
        print("  2. Start continuous monitoring")
        print("  3. Exit")
        print("=" * 70)

        choice = input("\nSelect option (1-3): ").strip()

        if choice == "1":
            sentinel.analyze_current_logs()
        elif choice == "2":
            interval = input("Enter monitoring interval in seconds (default: 60): ").strip()
            interval = int(interval) if interval.isdigit() else 60
            sentinel.start_monitoring(interval)
        elif choice == "3":
            print("👋 Exiting Sentinel-AI")
        else:
            print("❌ Invalid option")

    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        raise


if __name__ == "__main__":
    main()

