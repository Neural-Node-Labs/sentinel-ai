# ============================================================================
# FILE: utils/ingestion.py
# ============================================================================

from pathlib import Path
import chromadb
from chromadb.config import Settings
import os
from utils.logger_config import setup_logging
import logging
from dotenv import load_dotenv
load_dotenv()
# 1. Initialize the global configuration
setup_logging()
# 2. Get a logger for this specific file
logger = logging.getLogger(__name__)

class RAGIngestion:
    """ChromaDB ingestion for rules.md policy document"""

    def __init__(self, persist_dir: str | None = None):
        self.persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
        Path(self.persist_dir).mkdir(parents=True, exist_ok=True)

        self.client = chromadb.Client(Settings(
            persist_directory=self.persist_dir,
            anonymized_telemetry=False
        ))

        self.collection = self.client.get_or_create_collection(
            name="security_policies",
            metadata={"description": "Sentinel-AI security policy rules"}
        )

    def ingest_rules(self, rules_path: str = "rules.md") -> None:
        """
        Ingest rules.md into ChromaDB with chunking.

        Args:
            rules_path: Path to rules.md file
        """
        if not Path(rules_path).exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")

        with open(rules_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Split by sections (markdown headers)
        sections = self._split_into_sections(content)

        # Clear existing data
        existing_ids = self.collection.get()["ids"]
        if existing_ids:
            self.collection.delete(ids=existing_ids)

        # Add new documents
        ids = [f"rule_{i}" for i in range(len(sections))]
        self.collection.add(
            documents=sections,
            ids=ids,
            metadatas=[{"section": i, "source": "rules.md"} for i in range(len(sections))]
        )

        print(f"✓ Ingested {len(sections)} policy sections into ChromaDB")

    def query_policy(self, query: str, n_results: int = 3) -> list[str]:
        """
        Query the policy database.

        Args:
            query: Search query
            n_results: Number of results to return

        Returns:
            List of relevant policy sections
        """
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results
        )
        return results["documents"][0] if results["documents"] else []

    @staticmethod
    def _split_into_sections(content: str) -> list[str]:
        """Split markdown content into logical sections"""
        lines = content.split("\n")
        sections: list[str] = []
        current_section: list[str] = []

        for line in lines:
            if line.startswith("##") and current_section:
                sections.append("\n".join(current_section).strip())
                current_section = [line]
            else:
                current_section.append(line)

        if current_section:
            sections.append("\n".join(current_section).strip())

        return [s for s in sections if s]

