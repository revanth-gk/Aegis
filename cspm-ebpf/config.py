"""
config.py

Configuration settings for the Sentinel-Core Security AI Platform.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration variables mapped from the environment."""

    # Pinecone coordinates
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
    PINECONE_INDEX_HOST = os.getenv("PINECONE_INDEX_HOST")

    # Embedding provider selection ("google" or "openai")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "google")

    # Provider API Keys
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    GOOGLE_API_KEY_2 = os.getenv("GOOGLE_API_KEY_2")
    GOOGLE_API_KEY_3 = os.getenv("GOOGLE_API_KEY_3")
    GOOGLE_API_KEYS = [k for k in [GOOGLE_API_KEY, GOOGLE_API_KEY_2, GOOGLE_API_KEY_3] if k]
    
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

    # Specific embedding models
    GOOGLE_EMBEDDING_MODEL = "models/text-embedding-004"
    OPENAI_EMBEDDING_MODEL = "text-embedding-3-small"

    # LLM Models
    LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.0-pro")
    LLM_MODEL_FALLBACK = os.getenv("LLM_MODEL_FALLBACK", "gemini-2.0-flash")

    # Redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_CHANNEL = os.getenv("REDIS_CHANNEL", "sentinel-events")

# Validation checks
import logging
logger = logging.getLogger(__name__)

OFFLINE_MODE = os.getenv("OFFLINE_MODE", "false").lower() == "true"

if not OFFLINE_MODE:
    if not Config.PINECONE_API_KEY or not Config.PINECONE_INDEX_HOST:
        logger.warning("Missing PINECONE_API_KEY or PINECONE_INDEX_HOST. RAG will be disabled.")

    if Config.EMBEDDING_MODEL == "google" and not Config.GOOGLE_API_KEY:
        logger.warning("GOOGLE_API_KEY must be set when EMBEDDING_MODEL is 'google'.")
    elif Config.EMBEDDING_MODEL == "openai" and not Config.OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY must be set when EMBEDDING_MODEL is 'openai'.")
