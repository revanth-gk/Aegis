"""
executor.py

Kubernetes remediation action execution engine.

This module implements the Execution Engine component that executes
kubectl commands for SIGKILL and YAML patch remediation actions.

Validates: Requirements 6.1-6.6, 7.1-7.6, 8.1-8.3, 9.1-9.5, 12.1, 12.5
"""

import os
import subprocess
import logging
import time
import yaml
from typing import Tuple, Optional, Dict, Any
from functools import wraps

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker for Kubernetes API calls."""
    
    def __init__(self, failure_threshold: int = 10, cooldown_seconds: int = 300):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of consecutive failures before opening circuit
            cooldown_seconds: Cooldown period in seconds (default: 5 minutes)
        """
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.consecutive_failures = 0
        self.circuit_open_time: Optional[float] = None
        self.is_open = False
    
    def record_success(self):
        """Record successful execution."""
        self.consecutive_failures = 0
        self.is_open = False
        self.circuit_open_time = None
    
    def record_failure(self):
        """Record failed execution."""
        self.consecutive_failures += 1
        
        if self.consecutive_failures >= self.failure_threshold:
            self.is_open = True
            self.circuit_open_time = time.time()
            logger.error(
                f"Circuit breaker OPENED after {self.consecutive_failures} "
                f"consecutive failures. Cooldown: {self.cooldown_seconds}s"
            )
    
    def can_execute(self) -> Tuple[bool, str]:
        """
        Check if execution is allowed.
        
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        if not self.is_open:
            return True, ""
        
        # Check if cooldown period has elapsed
        if self.circuit_open_time is not None:
            elapsed = time.time() - self.circuit_open_time
            if elapsed >= self.cooldown_seconds:
                logger.info("Circuit breaker cooldown elapsed, resetting")
                self.is_open = False
                self.circuit_open_time = None
                self.consecutive_failures = 0
                return True, ""
        
        return False, f"Circuit breaker open (cooldown: {self.cooldown_seconds}s)"


def retry_with_backoff(max_retries: int = 3, initial_delay: float = 1.0):
    """
    Decorator for retrying operations with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds (doubles each retry)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except subprocess.TimeoutExpired as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} timed out, "
                            f"retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        logger.error(f"All {max_retries + 1} attempts failed")
                        raise
                except Exception as e:
                    # Don't retry non-timeout errors
                    raise
            
            # Should never reach here, but just in case
            raise last_exception
        
        return wrapper
    return decorator


class ExecutionEngine:
    """
    Executes Kubernetes remediation actions via kubectl.
    
    The Execution Engine handles both SIGKILL (process termination) and
    YAML (resource patch) remediation actions with proper authentication,
    retry logic, and circuit breaker protection.
    """
    
    def __init__(self, kubeconfig_path: Optional[str] = None, timeout: int = 30):
        """
        Initialize Execution Engine with Kubernetes authentication.
        
        Args:
            kubeconfig_path: Path to kubeconfig file (None for in-cluster auth)
            timeout: Command timeout in seconds
        """
        self.kubeconfig_path = kubeconfig_path
        self.timeout = timeout
        self.circuit_breaker = CircuitBreaker()
        self.is_in_cluster = self._detect_in_cluster()
        
        logger.info(
            f"Execution Engine initialized: "
            f"in_cluster={self.is_in_cluster}, "
            f"kubeconfig={kubeconfig_path}, "
            f"timeout={timeout}s"
        )
    
    def _detect_in_cluster(self) -> bool:
        """
        Detect if running in-cluster based on ServiceAccount token.
        
        Returns:
            True if in-cluster, False otherwise
        
        Requirements:
            9.5: Detect in-cluster vs external deployment
        """
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        in_cluster = os.path.exists(sa_token_path)
        
        if in_cluster:
            logger.info("Detected in-cluster deployment (ServiceAccount token found)")
        else:
            logger.info("Detected external deployment (no ServiceAccount token)")
        
        return in_cluster
    
    def _build_kubectl_command(self, args: list) -> list:
        """
        Build kubectl command with appropriate authentication.
        
        Args:
            args: kubectl command arguments
        
        Returns:
            Complete command list for subprocess
        """
        cmd = ["kubectl"]
        
        # Add kubeconfig if external deployment
        if not self.is_in_cluster and self.kubeconfig_path:
            cmd.extend(["--kubeconfig", self.kubeconfig_path])
        
        cmd.extend(args)
        return cmd
    
    @retry_with_backoff(max_retries=3, initial_delay=1.0)
    def _execute_kubectl(self, args: list, input_data: Optional[str] = None) -> Tuple[int, str, str]:
        """
        Execute kubectl command with retry and circuit breaker.
        
        Args:
            args: kubectl command arguments
            input_data: Optional stdin data for the command
        
        Returns:
            Tuple of (exit_code, stdout, stderr)
        
        Requirements:
            12.1: Retry up to 3 times with exponential backoff
            12.5: Circuit breaker with 5-minute cooldown
        """
        # Check circuit breaker
        can_execute, reason = self.circuit_breaker.can_execute()
        if not can_execute:
            raise RuntimeError(f"Circuit breaker open: {reason}")
        
        cmd = self._build_kubectl_command(args)
        
        try:
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Record success for circuit breaker
            self.circuit_breaker.record_success()
            
            return result.returncode, result.stdout, result.stderr
        
        except subprocess.TimeoutExpired as e:
            logger.error(f"kubectl command timed out after {self.timeout}s")
            self.circuit_breaker.record_failure()
            raise
        
        except Exception as e:
            logger.error(f"kubectl command failed: {e}")
            self.circuit_breaker.record_failure()
            raise
    
    def execute_sigkill(
        self,
        pod: str,
        namespace: str,
        pid: int,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute SIGKILL remediation (process termination).
        
        Args:
            pod: Pod name
            namespace: Kubernetes namespace
            pid: Process ID to terminate
            dry_run: If True, log action without executing
        
        Returns:
            Dict with keys: status, error_message
            status: "succeeded", "failed", or "dry_run"
        
        Requirements:
            6.1: Run kubectl exec kill -9
            6.2: Handle pod not found
            6.3: Handle process not found
            6.4: Mark succeeded on exit code 0
            6.5: Mark failed on non-zero exit code
            6.6: Extract pod, namespace, pid from event
            8.1: Log action in dry_run mode
            8.2: Record dry_run status
        """
        if dry_run:
            logger.info(
                f"[DRY RUN] Would execute SIGKILL: "
                f"kubectl exec {pod} -n {namespace} -- kill -9 {pid}"
            )
            return {
                "status": "dry_run",
                "error_message": ""
            }
        
        try:
            args = ["exec", pod, "-n", namespace, "--", "kill", "-9", str(pid)]
            exit_code, stdout, stderr = self._execute_kubectl(args)
            
            if exit_code == 0:
                logger.info(
                    f"SIGKILL succeeded: pod={pod}, namespace={namespace}, pid={pid}"
                )
                return {
                    "status": "succeeded",
                    "error_message": ""
                }
            else:
                # Check for specific error conditions
                error_msg = stderr.lower()
                
                if "not found" in error_msg and "pod" in error_msg:
                    logger.error(f"Pod not found: {pod} in namespace {namespace}")
                    return {
                        "status": "failed",
                        "error_message": f"Pod not found: {pod}"
                    }
                
                if "no such process" in error_msg or "process" in error_msg:
                    logger.warning(
                        f"Process not found (may have already exited): "
                        f"pid={pid} in pod={pod}"
                    )
                    # Process not existing is considered success (already terminated)
                    return {
                        "status": "succeeded",
                        "error_message": ""
                    }
                
                logger.error(
                    f"SIGKILL failed: exit_code={exit_code}, stderr={stderr}"
                )
                return {
                    "status": "failed",
                    "error_message": f"kubectl exec failed: {stderr}"
                }
        
        except Exception as e:
            logger.exception(f"SIGKILL execution failed: {e}")
            return {
                "status": "failed",
                "error_message": str(e)
            }
    
    def execute_yaml(
        self,
        yaml_patch: str,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute YAML patch remediation (resource configuration).
        
        Args:
            yaml_patch: YAML content to apply
            dry_run: If True, log action without executing
        
        Returns:
            Dict with keys: status, error_message
            status: "succeeded", "failed", or "dry_run"
        
        Requirements:
            7.1: Run kubectl apply -f
            7.2: Handle empty/missing yaml_patch
            7.3: Mark succeeded on exit code 0
            7.4: Mark failed on non-zero exit code
            7.5: Validate YAML syntax
            7.6: Skip execution on validation failure
            8.1: Log action in dry_run mode
            8.2: Record dry_run status
        """
        # Validate yaml_patch is not empty
        if not yaml_patch or not yaml_patch.strip():
            logger.error("YAML patch is empty or missing")
            return {
                "status": "failed",
                "error_message": "YAML patch is empty or missing"
            }
        
        # Validate YAML syntax
        try:
            yaml.safe_load(yaml_patch)
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML syntax: {e}")
            return {
                "status": "failed",
                "error_message": f"Invalid YAML syntax: {e}"
            }
        
        if dry_run:
            logger.info(
                f"[DRY RUN] Would execute YAML apply:\n{yaml_patch[:200]}..."
            )
            return {
                "status": "dry_run",
                "error_message": ""
            }
        
        try:
            args = ["apply", "-f", "-"]
            exit_code, stdout, stderr = self._execute_kubectl(args, input_data=yaml_patch)
            
            if exit_code == 0:
                logger.info(f"YAML apply succeeded: {stdout.strip()}")
                return {
                    "status": "succeeded",
                    "error_message": ""
                }
            else:
                logger.error(
                    f"YAML apply failed: exit_code={exit_code}, stderr={stderr}"
                )
                return {
                    "status": "failed",
                    "error_message": f"kubectl apply failed: {stderr}"
                }
        
        except Exception as e:
            logger.exception(f"YAML execution failed: {e}")
            return {
                "status": "failed",
                "error_message": str(e)
            }
