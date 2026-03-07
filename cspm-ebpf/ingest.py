#!/usr/bin/env python3
"""
Sentinel-Core Security AI Platform — Document Ingestion Script

Ingests security knowledge from two sources:
  1. MITRE ATT&CK techniques (JSON format)
  2. Azure Security Benchmark (PDF format)

Chunks, embeds via google-genai SDK, and upserts to Pinecone v3.
"""

import json
import logging
import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

from dotenv import load_dotenv
from pinecone import Pinecone
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader
from langchain_huggingface import HuggingFaceEmbeddings

load_dotenv()

# Configure structured logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIG (read directly from env, no Config import needed)
# ============================================================================

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_HOST = os.getenv("PINECONE_INDEX_HOST")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
EMBEDDING_MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"


class SentinelIngestor:
    """Handles the ingestion pipeline for security documents into Pinecone."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

        if not PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY environment variable is required.")
        if not PINECONE_INDEX_HOST:
            raise ValueError("PINECONE_INDEX_HOST environment variable is required.")
        if not GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY environment variable is required.")

        # Pinecone v3: client without host, index with host
        self._pc_client = Pinecone(api_key=PINECONE_API_KEY)
        self._pc_index = self._pc_client.Index(host=PINECONE_INDEX_HOST)
        logger.info(f"Pinecone index connected via host: {PINECONE_INDEX_HOST}")

        # Local HuggingFace embeddings (768-dim)
        self._embeddings_model = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME)
        logger.info(f"HuggingFace embedding client initialized ({EMBEDDING_MODEL_NAME})")

        self.stats = {
            "mitre": {"loaded": 0, "embedded": 0, "upserted": 0, "skipped": 0},
            "azure": {"loaded": 0, "embedded": 0, "upserted": 0, "skipped": 0}
        }

    def generate_id(self, text: str) -> str:
        """Generate a deterministic ID based on the MD5 hash of the chunk text."""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def load_mitre_json(self, file_path: str) -> List[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK file not found: {file_path}")

        logger.info(f"Loading MITRE ATT&CK from {file_path}...")

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        valid_techniques = []

        # Check if it's a STIX bundle (enterprise-attack.json format)
        if isinstance(data, dict) and data.get('type') == 'bundle' and 'objects' in data:
            logger.info("Detected STIX bundle format for MITRE Data")
            for obj in data['objects']:
                if obj.get('type') == 'attack-pattern':
                    # Extract Technique ID
                    tech_id = "UNKNOWN"
                    for ext_ref in obj.get('external_references', []):
                        if ext_ref.get('source_name') == 'mitre-attack':
                            tech_id = ext_ref.get('external_id', 'UNKNOWN')
                            break
                    
                    if tech_id == "UNKNOWN":
                        continue
                        
                    # Extract Tactic
                    tactics = []
                    for kc in obj.get('kill_chain_phases', []):
                        if kc.get('kill_chain_name') == 'mitre-attack':
                            tactics.append(kc.get('phase_name', ''))
                    
                    tactic = tactics[0] if tactics else "unknown-tactic"
                    
                    valid_techniques.append({
                        'technique_id': tech_id,
                        'name': obj.get('name', 'Unknown Technique'),
                        'description': obj.get('description', ''),
                        'tactic': tactic
                    })
        else:
            # Fallback to simple format
            logger.info("Detected simple format for MITRE Data")
            if isinstance(data, list):
                techniques = data
            elif isinstance(data, dict) and 'techniques' in data:
                techniques = data['techniques']
            else:
                raise ValueError("Invalid MITRE JSON format: expected STIX bundle, list, or dict with 'techniques'")

            for tech in techniques:
                if all(k in tech for k in ['technique_id', 'name', 'description', 'tactic']):
                    valid_techniques.append(tech)
                else:
                    logger.warning(f"Skipping technique missing fields: {tech.get('technique_id', 'UNKNOWN')}")

        self.stats["mitre"]["loaded"] = len(valid_techniques)
        logger.info(f"Loaded {len(valid_techniques)} MITRE techniques")

        return valid_techniques

    def load_azure_pdf(self, file_path: str) -> List[str]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Azure Security Benchmark PDF not found: {file_path}")

        logger.info(f"Loading Azure Security Benchmark from {file_path}...")

        loader = PyPDFLoader(str(path))
        documents = loader.load()

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=100,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )

        chunks = text_splitter.split_documents(documents)
        chunk_texts = [chunk.page_content for chunk in chunks]

        self.stats["azure"]["loaded"] = len(chunk_texts)
        logger.info(f"Created {len(chunk_texts)} Azure PDF chunks")

        return chunk_texts

    def chunk_mitre_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.info("Formatting MITRE techniques into chunks...")

        chunks = []
        for tech in techniques:
            chunk_text = (
                f"Technique {tech['technique_id']} - {tech['name']} | "
                f"Tactic: {tech['tactic']} | {tech['description']}"
            )

            chunks.append({
                "text": chunk_text,
                "technique_id": tech['technique_id'],
                "name": tech['name'],
                "tactic": tech['tactic']
            })

        self.stats["mitre"]["embedded"] = len(chunks)
        logger.info(f"Formatted {len(chunks)} MITRE chunks")

        return chunks

    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using HuggingFace sentence-transformers."""
        logger.info(f"Generating embeddings for {len(texts)} texts using local model...")
        return self._embeddings_model.embed_documents(texts)

    def upsert_to_pinecone(
        self,
        namespace: str,
        chunks: List[Dict[str, Any]],
        embeddings: List[List[float]]
    ) -> None:
        logger.info(f"Upserting to Pinecone namespace '{namespace}'...")

        vectors = []
        for chunk, embedding in zip(chunks, embeddings):
            vector_id = self.generate_id(chunk["text"])

            metadata = {
                "source": namespace,
                "text": chunk["text"]
            }
            if namespace == "mitre":
                metadata.update({
                    "technique_id": chunk.get("technique_id"),
                    "name": chunk.get("name"),
                    "tactic": chunk.get("tactic")
                })

            vectors.append({
                "id": vector_id,
                "values": embedding,
                "metadata": metadata
            })

        batch_size = 100
        upserted_count = 0
        skipped_count = 0

        for i in range(0, len(vectors), batch_size):
            batch = vectors[i:i + batch_size]

            if not self.dry_run:
                # Idempotency: check existing
                batch_ids = [v["id"] for v in batch]
                try:
                    fetch_response = self._pc_index.fetch(ids=batch_ids, namespace=namespace)
                    existing_ids = set(fetch_response.get('vectors', {}).keys())
                except Exception:
                    existing_ids = set()

                vectors_to_upsert = [v for v in batch if v["id"] not in existing_ids]
                skipped = len(batch) - len(vectors_to_upsert)
                skipped_count += skipped

                if vectors_to_upsert:
                    self._pc_index.upsert(vectors=vectors_to_upsert, namespace=namespace)
                    upserted_count += len(vectors_to_upsert)
            else:
                logger.info(f"[DRY-RUN] Would upsert batch of {len(batch)} vectors.")
                upserted_count += len(batch)
                skipped = 0

            processed = min(i + batch_size, len(vectors))
            logger.info(
                f"Processed {processed}/{len(vectors)} vectors "
                f"(Upserted: {len(batch) - skipped}, Skipped: {skipped})"
            )

        self.stats[namespace]["upserted"] += upserted_count
        self.stats[namespace]["skipped"] += skipped_count

    def ingest_mitre(self, json_path: str) -> None:
        logger.info("=" * 60)
        logger.info("MITRE ATT&CK Ingestion Pipeline")
        logger.info("=" * 60)

        techniques = self.load_mitre_json(json_path)
        chunks = self.chunk_mitre_techniques(techniques)
        texts = [chunk["text"] for chunk in chunks]

        logger.info("Generating embeddings for MITRE chunks...")
        embeddings = self.generate_embeddings(texts)

        self.upsert_to_pinecone(
            namespace="mitre",
            chunks=chunks,
            embeddings=embeddings
        )

        logger.info("MITRE ingestion complete")

    def ingest_azure(self, pdf_path: str) -> None:
        logger.info("=" * 60)
        logger.info("Azure Security Benchmark Ingestion Pipeline")
        logger.info("=" * 60)

        chunk_texts = self.load_azure_pdf(pdf_path)
        chunks = [{"text": text} for text in chunk_texts]

        logger.info("Generating embeddings for Azure chunks...")
        embeddings = self.generate_embeddings(chunk_texts)

        self.upsert_to_pinecone(
            namespace="azure",
            chunks=chunks,
            embeddings=embeddings
        )

        logger.info("Azure ingestion complete")

    def print_summary(self) -> None:
        logger.info("=" * 60)
        logger.info("INGESTION SUMMARY")
        logger.info("=" * 60)

        for source in ["mitre", "azure"]:
            stats = self.stats[source]
            logger.info(f"{source.upper()}:")
            logger.info(f"  Loaded:    {stats['loaded']}")
            logger.info(f"  Embedded:  {stats['embedded']}")
            logger.info(f"  Upserted:  {stats['upserted']}")
            logger.info(f"  Skipped:   {stats['skipped']}")

        total_upserted = sum(s["upserted"] for s in self.stats.values())
        logger.info(f"TOTAL VECTORS UPSERTED: {total_upserted}")
        logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel-Core — Document Ingestion Script"
    )
    parser.add_argument(
        "mitre_path", nargs="?", default="enterprise-attack.json",
        help="Path to MITRE JSON file"
    )
    parser.add_argument(
        "azure_path", nargs="?", default="CIS_Microsoft_Azure_Foundations_Benchmark_v1.0.0.pdf",
        help="Path to Azure PDF file"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Process and log but do not upsert to Pinecone"
    )
    args = parser.parse_args()

    logger.info("Starting Sentinel-Core Ingestion Pipeline")
    logger.info(f"MITRE file: {args.mitre_path}")
    logger.info(f"Azure file: {args.azure_path}")

    if args.dry_run:
        logger.info("DRY-RUN MODE ENABLED — No changes will be made to Pinecone")

    try:
        ingestor = SentinelIngestor(dry_run=args.dry_run)
        ingestor.ingest_mitre(args.mitre_path)
        ingestor.ingest_azure(args.azure_path)
        ingestor.print_summary()
        logger.info("Ingestion completed successfully!")

    except FileNotFoundError as e:
        logger.error(f"FILE NOT FOUND: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"INVALID JSON: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"CONFIGURATION ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"UNEXPECTED ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
