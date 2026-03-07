# Implementation Plan: RemediationAgent

## Overview

This plan implements the RemediationAgent as a new LangGraph node (Node D) in the Sentinel-Core pipeline. The implementation follows a modular architecture with five core components: Config Manager, Decision Gate, Routing Engine, Execution Engine, and Audit Logger. The agent integrates after report_generator, processes true positive events with confidence-based gating, and executes Kubernetes remediation actions (YAML patches or SIGKILL) based on MITRE tactics.

## Tasks

- [-] 1. Create remediation module structure and configuration
  - Create `cspm-ebpf/remediation/` directory
  - Create `cspm-ebpf/remediation/__init__.py` with module exports
  - Create `cspm-ebpf/remediation/config.py` with RemediationConfig class
  - Implement environment variable loading for autonomy_mode, dry_run, confidence thresholds, and Kubernetes auth settings
  - Add configuration validation with sensible defaults (dry_run=True, autonomy_mode="tiered", sigkill_threshold=0.92, yaml_threshold=0.95)
  - _Requirements: 5.5, 8.4, 11.1, 11.5_

- [ ]* 1.1 Write unit tests for configuration loading
  - Test environment variable parsing
  - Test default value fallback
  - Test configuration validation
  - _Requirements: 11.4_

- [ ] 2. Extend SentinelState and update orchestrator routing
  - [ ] 2.1 Add remediation fields to SentinelState TypedDict in orchestrator.py
    - Add remediation_status: str field
    - Add remediation_action: str field
    - Add remediation_timestamp: str field
    - Add remediation_error: str field (optional)
    - _Requirements: 16.2, 16.3, 16.5_

  - [ ] 2.2 Create remediation_or_end routing function in orchestrator.py
    - Check if state["guide_grade"] == "TP"
    - Return "remediation_agent" for TP events
    - Return END for non-TP events
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_

  - [ ] 2.3 Update build_sentinel_graph to integrate remediation_agent node
    - Add remediation_agent node to workflow
    - Replace report_or_end with remediation_or_end on report_generator conditional edge
    - Add conditional edge from remediation_agent to END
    - _Requirements: 1.1, 1.3_

- [ ]* 2.4 Write integration tests for graph routing
  - Test TP events route to remediation_agent
  - Test BP/FP events skip remediation_agent
  - Test remediation_agent routes to END
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 3. Checkpoint - Verify graph topology changes
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement Decision Gate component
  - [ ] 4.1 Create cspm-ebpf/remediation/decision_gate.py
    - Implement DecisionGate class with evaluate_action method
    - Accept confidence_score, action_type, and config as parameters
    - Return approval decision (bool) and rejection reason (str or None)
    - Implement confidence threshold checks (>= 0.92 for SIGKILL, >= 0.95 for YAML)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [ ]* 4.2 Write property test for Decision Gate
    - **Property 1: Confidence monotonicity - Higher confidence never decreases approval likelihood**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4**

  - [ ]* 4.3 Write unit tests for Decision Gate
    - Test SIGKILL approval at confidence 0.92 and above
    - Test SIGKILL rejection below 0.92
    - Test YAML approval at confidence 0.95 and above
    - Test YAML rejection below 0.95
    - Test rejection reason formatting
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 5. Implement Routing Engine component
  - [ ] 5.1 Create cspm-ebpf/remediation/routing_engine.py
    - Implement RoutingEngine class with determine_action method
    - Accept mitre_techniques list as parameter
    - Parse MITRE tactic strings from mitre_techniques field
    - Implement tactic-to-action mapping (Execution/Privilege Escalation/Credential Access → SIGKILL)
    - Implement tactic-to-action mapping (Persistence/Defense Evasion → YAML)
    - Implement priority logic: SIGKILL takes precedence if any SIGKILL-eligible tactic present
    - Default to YAML for unrecognized tactics
    - Return action_type string ("SIGKILL" or "YAML")
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 17.1, 17.2, 17.3_

  - [ ]* 5.2 Write property test for Routing Engine
    - **Property 2: Action determinism - Same tactics always produce same action**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7**

  - [ ]* 5.3 Write unit tests for Routing Engine
    - Test SIGKILL selection for Execution tactic
    - Test SIGKILL selection for Privilege Escalation tactic
    - Test SIGKILL selection for Credential Access tactic
    - Test YAML selection for Persistence tactic
    - Test YAML selection for Defense Evasion tactic
    - Test SIGKILL priority with mixed tactics
    - Test YAML default for unrecognized tactics
    - Test empty tactics list handling
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 17.3_

- [ ] 6. Implement Audit Logger component
  - [ ] 6.1 Create cspm-ebpf/remediation/audit_logger.py
    - Implement AuditLogger class with Redis client initialization
    - Implement log_action method accepting event_id, action_type, confidence_score, autonomy_mode, execution_status, error_message, mitre_techniques
    - Generate audit record with timestamp, all parameters, and unique audit_id
    - Implement Redis persistence with key pattern "audit:{event_id}:{timestamp}"
    - Set TTL to 90 days (7776000 seconds)
    - Implement batch writing: buffer up to 10 records or 1-second intervals
    - Implement query_by_event_id method for idempotency checks
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 13.4, 17.4_

  - [ ]* 6.2 Write unit tests for Audit Logger
    - Test audit record creation with all fields
    - Test Redis key formatting
    - Test TTL setting
    - Test batch write buffering
    - Test query_by_event_id retrieval
    - Mock Redis client for testing
    - _Requirements: 10.1, 10.2, 10.5, 10.6, 13.4_

- [ ] 7. Checkpoint - Verify core components
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement Execution Engine component
  - [ ] 8.1 Create cspm-ebpf/remediation/executor.py
    - Implement ExecutionEngine class with Kubernetes client initialization
    - Implement hybrid authentication: detect in-cluster vs external deployment
    - Load ServiceAccount token from /var/run/secrets/kubernetes.io/serviceaccount/token for in-cluster
    - Load kubeconfig from config path for external deployment
    - Implement execute_sigkill method accepting pod, namespace, pid, dry_run
    - Implement execute_yaml method accepting yaml_patch, dry_run
    - Add YAML syntax validation before execution
    - Implement kubectl command execution via subprocess
    - Parse kubectl exit codes and error messages
    - Return execution result with status (succeeded/failed/dry_run) and error message
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 9.4, 9.5_

  - [ ] 8.2 Implement retry logic with exponential backoff
    - Add retry decorator for kubectl commands
    - Retry up to 3 times on timeout
    - Implement exponential backoff (1s, 2s, 4s)
    - _Requirements: 12.1_

  - [ ] 8.3 Implement circuit breaker for Kubernetes API
    - Track consecutive failure count
    - Open circuit after 10 consecutive failures
    - Implement 5-minute cooldown period
    - Reset failure count on successful execution
    - _Requirements: 12.5_

  - [ ]* 8.4 Write unit tests for Execution Engine
    - Test SIGKILL command formatting
    - Test YAML apply command formatting
    - Test dry_run mode (no actual execution)
    - Test exit code parsing
    - Test error message extraction
    - Test authentication detection logic
    - Test YAML validation
    - Mock subprocess calls for testing
    - _Requirements: 6.1, 6.4, 6.5, 7.1, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.3, 9.5_

  - [ ]* 8.5 Write unit tests for retry and circuit breaker
    - Test retry on timeout
    - Test exponential backoff timing
    - Test circuit breaker opening
    - Test circuit breaker cooldown
    - Test circuit breaker reset
    - _Requirements: 12.1, 12.5_

- [ ] 9. Implement main RemediationAgent orchestrator
  - [ ] 9.1 Create cspm-ebpf/remediation/agent.py
    - Implement remediation_agent function matching LangGraph node signature
    - Accept state: SentinelState parameter
    - Initialize all components (ConfigManager, DecisionGate, RoutingEngine, ExecutionEngine, AuditLogger)
    - Implement event validation: check for required fields (event_id, mitre_techniques, confidence_score, guide_grade)
    - Implement idempotency check: query audit trail for recent successful remediation
    - Skip re-execution if successful remediation within 5 minutes
    - Allow retry if failed remediation older than 1 minute
    - Extract event context: pod, namespace, pid from raw_event
    - Call RoutingEngine to determine action type
    - Call DecisionGate to evaluate confidence
    - Implement autonomy mode logic: autonomous (no confirmation), tiered (confirm SIGKILL only), human-in-loop (confirm all)
    - Call ExecutionEngine for approved actions
    - Call AuditLogger for all decisions and outcomes
    - Update state with remediation_status, remediation_action, remediation_timestamp
    - Preserve all existing state fields
    - Return updated state dictionary
    - _Requirements: 1.4, 1.5, 2.4, 2.5, 5.1, 5.2, 5.3, 5.4, 16.1, 16.2, 16.3, 16.4, 16.5, 18.1, 18.2, 18.3, 18.4, 18.5_

  - [ ] 9.2 Implement error handling and logging
    - Wrap all operations in try-except blocks
    - Log errors with structured JSON format (level, timestamp, event_id, message)
    - Set remediation_status to "error" on unhandled exceptions
    - Never crash the LangGraph pipeline
    - _Requirements: 12.4, 14.5_

  - [ ]* 9.3 Write integration tests for RemediationAgent
    - Test full TP event processing flow
    - Test confidence rejection flow
    - Test autonomy mode variations
    - Test idempotency with duplicate events
    - Test error handling with missing fields
    - Test state preservation
    - Mock all external dependencies (Kubernetes, Redis)
    - _Requirements: 1.4, 1.5, 2.1, 3.5, 5.1, 5.2, 5.3, 16.1, 16.2, 16.3, 16.5, 18.1, 18.2, 18.3_

- [ ] 10. Implement configuration REST API endpoint
  - [ ] 10.1 Create cspm-ebpf/remediation/config_api.py
    - Implement Flask blueprint for /api/remediation/config endpoint
    - Implement GET handler returning current configuration
    - Implement POST handler accepting configuration updates
    - Validate configuration updates before applying
    - Return 400 Bad Request for invalid configuration
    - Log all configuration changes to audit trail
    - Support updating autonomy_mode, dry_run, confidence thresholds, tactic routing
    - _Requirements: 11.2, 11.3, 11.4, 11.5, 11.6_

  - [ ]* 10.2 Write unit tests for configuration API
    - Test GET endpoint returns current config
    - Test POST endpoint updates configuration
    - Test POST validation rejects invalid config
    - Test configuration change logging
    - _Requirements: 11.2, 11.3, 11.4, 11.6_

- [ ] 11. Implement observability and monitoring
  - [ ] 11.1 Add Prometheus metrics to remediation/agent.py
    - Implement Counter for actions_total (labels: action_type, status)
    - Implement Counter for actions_succeeded (labels: action_type)
    - Implement Counter for actions_failed (labels: action_type, reason)
    - Implement Histogram for processing_duration_seconds
    - Increment metrics in remediation_agent function
    - _Requirements: 14.1_

  - [ ] 11.2 Create cspm-ebpf/remediation/health.py
    - Implement /health endpoint handler
    - Check Kubernetes API reachability
    - Check Redis reachability
    - Return 200 OK if all dependencies healthy
    - Return 503 Service Unavailable if any dependency unreachable
    - Include dependency status details in response body
    - _Requirements: 14.2, 14.3, 14.4_

  - [ ]* 11.3 Write unit tests for health endpoint
    - Test 200 OK with all dependencies healthy
    - Test 503 with Kubernetes unreachable
    - Test 503 with Redis unreachable
    - Mock dependency checks
    - _Requirements: 14.2, 14.3, 14.4_

- [ ] 12. Implement RBAC validation and security checks
  - [ ] 12.1 Create cspm-ebpf/remediation/rbac_validator.py
    - Implement validate_service_account function
    - Check ServiceAccount permissions using kubectl auth can-i
    - Verify pods/exec permission in monitored namespaces
    - Verify configmaps/apply permission in monitored namespaces
    - Reject cluster-admin and namespace-admin roles
    - Reject delete permissions
    - Log validation results
    - Raise exception if permissions are overly permissive
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

  - [ ] 12.2 Integrate RBAC validation into agent startup
    - Call validate_service_account during RemediationAgent initialization
    - Refuse to start if validation fails
    - Log RBAC validation status
    - _Requirements: 15.5_

  - [ ]* 12.3 Write unit tests for RBAC validation
    - Test validation passes with correct permissions
    - Test validation fails with cluster-admin role
    - Test validation fails with delete permissions
    - Test validation fails with overly broad namespace access
    - Mock kubectl auth can-i calls
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

- [ ] 13. Checkpoint - Verify complete integration
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Wire components together and update main application
  - [ ] 14.1 Update cspm-ebpf/remediation/__init__.py
    - Export remediation_agent function
    - Export RemediationConfig class
    - Export health check handler
    - Export config API blueprint
    - _Requirements: 1.1_

  - [ ] 14.2 Update cspm-ebpf/orchestrator.py imports
    - Import remediation_agent from remediation module
    - Register remediation_agent node in build_sentinel_graph
    - _Requirements: 1.1, 1.3_

  - [ ] 14.3 Update cspm-ebpf/config.py
    - Add remediation configuration variables
    - Add REMEDIATION_AUTONOMY_MODE environment variable
    - Add REMEDIATION_DRY_RUN environment variable
    - Add REMEDIATION_SIGKILL_THRESHOLD environment variable
    - Add REMEDIATION_YAML_THRESHOLD environment variable
    - Add KUBECONFIG_PATH environment variable
    - _Requirements: 11.1, 11.5_

  - [ ] 14.4 Update cspm-ebpf/main.py or live_backend.py
    - Register remediation config API blueprint
    - Register remediation health endpoint
    - Initialize Prometheus metrics registry
    - _Requirements: 11.2, 14.1, 14.2_

  - [ ] 14.5 Update cspm-ebpf/requirements.txt
    - Add kubernetes Python client library
    - Add prometheus_client library
    - Add pyyaml library (if not already present)
    - _Requirements: 6.1, 7.1, 9.1, 14.1_

- [ ]* 14.6 Write end-to-end integration tests
  - Test complete pipeline from event ingestion to remediation
  - Test TP event triggers remediation
  - Test BP/FP events skip remediation
  - Test dry_run mode prevents actual execution
  - Test audit trail persistence
  - Test metrics collection
  - Use test Kubernetes cluster or mock
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 8.1, 8.2, 10.1, 14.1_

- [ ] 15. Create documentation and examples
  - [ ] 15.1 Create cspm-ebpf/remediation/README.md
    - Document architecture and component responsibilities
    - Document configuration options and environment variables
    - Document autonomy modes and confidence thresholds
    - Document RBAC requirements and ServiceAccount setup
    - Provide example Kubernetes manifests for ServiceAccount and RoleBinding
    - Document API endpoints and usage examples
    - Document metrics and monitoring setup
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 8.4, 9.1, 9.2, 11.1, 11.2, 14.1, 15.1, 15.2_

  - [ ] 15.2 Create example configuration files
    - Create example .env with remediation variables
    - Create example ServiceAccount YAML
    - Create example RoleBinding YAML with minimal permissions
    - Create example deployment manifest with in-cluster auth
    - _Requirements: 9.1, 9.2, 15.1, 15.2, 15.3_

- [ ] 16. Final checkpoint - Complete system validation
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at logical breakpoints
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation uses Python to match the existing Sentinel-Core codebase
- All Kubernetes operations use kubectl subprocess calls for simplicity and compatibility
- Redis is used for audit trail persistence with 90-day TTL
- Default configuration is conservative: dry_run=True, autonomy_mode="tiered"
- RBAC validation ensures least-privilege security posture
