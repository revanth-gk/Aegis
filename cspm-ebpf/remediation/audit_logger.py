"""
audit_logger.py

Audit trail logging for remediation actions.

This module implements the Audit Logger component that records all
remediation decisions and outcomes to Redis for compliance and debugging.

Validates: Requirements 10.1-10.6, 13.4, 17.4
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from threading import Lock
import uuid

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Records remediation actions to Redis with batch writing and TTL.
    
    The Audit Logger maintains a comprehensive audit trail of all remediation
    decisions and outcomes, supporting compliance requirements and debugging.
    Records are batched for performance and stored with 90-day TTL.
    """
    
    # 90 days in seconds
    TTL_SECONDS = 90 * 24 * 60 * 60  # 7776000 seconds
    
    # Batch configuration
    BATCH_SIZE = 10
    BATCH_INTERVAL_SECONDS = 1.0
    
    def __init__(self, redis_client=None):
        """
        Initialize Audit Logger with Redis client.
        
        Args:
            redis_client: Redis client instance (optional for testing)
                If None, will attempt to initialize from environment
        """
        self.redis_client = redis_client
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_lock = Lock()
        self._last_flush_time = time.time()
        
        # Initialize Redis client if not provided
        if self.redis_client is None:
            self._init_redis_client()
        
        logger.info(
            f"Audit Logger initialized: batch_size={self.BATCH_SIZE}, "
            f"batch_interval={self.BATCH_INTERVAL_SECONDS}s, TTL={self.TTL_SECONDS}s"
        )
    
    def _init_redis_client(self):
        """Initialize Redis client from environment variables."""
        try:
            import redis
            import os
            
            redis_host = os.getenv("REDIS_HOST", "localhost")
            redis_port = int(os.getenv("REDIS_PORT", "6379"))
            redis_db = int(os.getenv("REDIS_DB", "0"))
            redis_password = os.getenv("REDIS_PASSWORD")
            
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password,
                decode_responses=True
            )
            
            # Test connection
            self.redis_client.ping()
            logger.info(f"Redis client connected: {redis_host}:{redis_port}")
        
        except Exception as e:
            logger.error(f"Failed to initialize Redis client: {e}")
            self.redis_client = None
    
    def log_action(
        self,
        event_id: str,
        action_type: str,
        confidence_score: float,
        autonomy_mode: str,
        execution_status: str,
        error_message: Optional[str] = None,
        mitre_techniques: Optional[List[dict]] = None
    ) -> None:
        """
        Log a remediation action to the audit trail.
        
        Args:
            event_id: Unique identifier for the security event
            action_type: Type of action ("SIGKILL", "YAML", or empty)
            confidence_score: ML model confidence (0.0-1.0)
            autonomy_mode: Autonomy mode used ("autonomous", "tiered", "human-in-loop")
            execution_status: Status ("succeeded", "failed", "skipped", "dry_run", "duplicate_skipped")
            error_message: Error message if action failed (optional)
            mitre_techniques: List of MITRE technique dicts (optional)
        
        Requirements:
            10.1: Create audit record keyed by event_id
            10.2: Record all required fields
            10.3: Record rejection reasons
            10.4: Record error messages and stack traces
            10.5: Persist to Redis with 90-day TTL
            13.4: Batch writes (10 records or 1-second intervals)
            17.4: Record full list of mitre_techniques
        """
        # Generate audit record
        audit_record = {
            "audit_id": str(uuid.uuid4()),
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "confidence_score": confidence_score,
            "autonomy_mode": autonomy_mode,
            "execution_status": execution_status,
            "error_message": error_message or "",
            "mitre_techniques": mitre_techniques or []
        }
        
        logger.debug(
            f"Audit record created: event_id={event_id}, "
            f"action={action_type}, status={execution_status}"
        )
        
        # Add to batch buffer
        with self._batch_lock:
            self._batch_buffer.append(audit_record)
            
            # Check if we should flush
            should_flush = (
                len(self._batch_buffer) >= self.BATCH_SIZE or
                (time.time() - self._last_flush_time) >= self.BATCH_INTERVAL_SECONDS
            )
            
            if should_flush:
                self._flush_batch()
    
    def _flush_batch(self) -> None:
        """
        Flush buffered audit records to Redis.
        
        This method should be called with _batch_lock held.
        """
        if not self._batch_buffer:
            return
        
        if self.redis_client is None:
            logger.warning(
                f"Redis client not available, dropping {len(self._batch_buffer)} audit records"
            )
            self._batch_buffer.clear()
            self._last_flush_time = time.time()
            return
        
        records_to_write = self._batch_buffer.copy()
        self._batch_buffer.clear()
        self._last_flush_time = time.time()
        
        # Write records to Redis
        try:
            pipeline = self.redis_client.pipeline()
            
            for record in records_to_write:
                # Key format: audit:{event_id}:{timestamp}
                key = f"audit:{record['event_id']}:{record['timestamp']}"
                value = json.dumps(record)
                
                # Set with TTL
                pipeline.setex(key, self.TTL_SECONDS, value)
            
            pipeline.execute()
            
            logger.info(f"Flushed {len(records_to_write)} audit records to Redis")
        
        except Exception as e:
            logger.error(f"Failed to flush audit records to Redis: {e}")
            # Re-buffer failed records for retry
            with self._batch_lock:
                self._batch_buffer.extend(records_to_write)
    
    def query_by_event_id(self, event_id: str) -> List[Dict[str, Any]]:
        """
        Query audit records for a specific event ID.
        
        Args:
            event_id: Event ID to query
        
        Returns:
            List of audit records (dicts) for the event, sorted by timestamp
        
        Requirements:
            10.6: Support querying by event_id
            18.1: Check audit trail for recent remediation
        """
        if self.redis_client is None:
            logger.warning("Redis client not available for query")
            return []
        
        try:
            # Scan for keys matching pattern
            pattern = f"audit:{event_id}:*"
            keys = []
            
            for key in self.redis_client.scan_iter(match=pattern):
                keys.append(key)
            
            if not keys:
                return []
            
            # Fetch all records
            records = []
            for key in keys:
                value = self.redis_client.get(key)
                if value:
                    record = json.loads(value)
                    records.append(record)
            
            # Sort by timestamp
            records.sort(key=lambda r: r.get("timestamp", ""))
            
            logger.debug(f"Found {len(records)} audit records for event_id={event_id}")
            return records
        
        except Exception as e:
            logger.error(f"Failed to query audit records: {e}")
            return []
    
    def force_flush(self) -> None:
        """
        Force flush any buffered audit records.
        
        Useful for shutdown or testing scenarios.
        """
        with self._batch_lock:
            if self._batch_buffer:
                logger.info(f"Force flushing {len(self._batch_buffer)} audit records")
                self._flush_batch()
