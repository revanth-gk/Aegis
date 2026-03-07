# Requirements Document: RemediationAgent

## Introduction

The RemediationAgent is a security orchestration component that autonomously executes remediation actions for ML-triaged security events in Kubernetes environments. It integrates into the Sentinel-Core LangGraph pipeline as Node D, processing true positive security events with confidence-gated execution of YAML patches and process termination actions. The system supports multiple autonomy modes, maintains comprehensive audit trails, and enforces conservative safety constraints to prevent unintended disruption.

## Glossary

- **RemediationAgent**: The main orchestration component (Node D) that processes security events and executes remediation actions
- **LangGraph**: The orchestration framework managing the security event processing pipeline
- **event_router**: Node A in the pipeline that performs initial ML-based event grading
- **rag_retriever**: Node B that enriches events with MITRE ATT&CK context
- **report_generator**: Node C that generates security reports and YAML remediation patches
- **TP_Event**: True Positive security event (grade == "TP")
- **BP_Event**: Benign Positive security event (grade == "BP")
- **FP_Event**: False Positive security event (grade == "FP")
- **Config_Manager**: Component responsible for loading and managing runtime configuration
- **Decision_Gate**: Component that evaluates confidence scores against thresholds
- **Routing_Engine**: Component that determines appropriate remediation action type
- **Execution_Engine**: Component that executes kubectl commands against Kubernetes
- **Audit_Logger**: Component that records all remediation decisions and outcomes
- **SIGKILL_Action**: Process termination remediation via kubectl exec kill -9
- **YAML_Action**: Kubernetes resource patch remediation via kubectl apply
- **Confidence_Score**: ML model confidence value between 0.0 and 1.0
- **MITRE_Tactic**: High-level adversary goal from MITRE ATT&CK framework
- **Autonomy_Mode**: Configuration setting controlling human approval requirements
- **Redis_Store**: Persistent storage for audit trail keyed by event_id
- **ServiceAccount**: Kubernetes in-cluster authentication mechanism
- **kubeconfig**: External cluster authentication configuration file

## Requirements

### Requirement 1: LangGraph Pipeline Integration

**User Story:** As a security orchestration system, I want the RemediationAgent to integrate seamlessly into the existing LangGraph pipeline, so that remediation occurs automatically after report generation for true positive events.

#### Acceptance Criteria

1. WHEN the report_generator node completes with grade == "TP", THE RemediationAgent SHALL receive the event as input
2. WHEN the report_generator node completes with grade != "TP", THE LangGraph SHALL route to END without invoking RemediationAgent
3. WHEN RemediationAgent completes execution, THE LangGraph SHALL route to END state
4. THE RemediationAgent SHALL consume the complete state dictionary from report_generator including event_id, mitre_techniques, confidence_score, and yaml_patch fields
5. THE RemediationAgent SHALL preserve all upstream state fields when returning control to LangGraph

### Requirement 2: Event Processing and Filtering

**User Story:** As a security operator, I want the system to only process true positive events, so that remediation actions are never taken on false positives or benign activity.

#### Acceptance Criteria

1. WHEN an event with grade == "TP" is received, THE RemediationAgent SHALL process the event for remediation
2. WHEN an event with grade == "BP" is received, THE RemediationAgent SHALL NOT be invoked
3. WHEN an event with grade == "FP" is received, THE RemediationAgent SHALL NOT be invoked
4. WHEN an event lacks a grade field, THE RemediationAgent SHALL log an error and skip remediation
5. THE RemediationAgent SHALL validate that required fields (event_id, mitre_techniques, confidence_score) are present before processing

### Requirement 3: Confidence-Based Decision Gating

**User Story:** As a security engineer, I want remediation actions gated by confidence thresholds, so that only high-confidence detections trigger potentially disruptive actions.

#### Acceptance Criteria

1. WHEN confidence_score >= 0.92 AND action type is SIGKILL, THE Decision_Gate SHALL approve the action
2. WHEN confidence_score < 0.92 AND action type is SIGKILL, THE Decision_Gate SHALL reject the action
3. WHEN confidence_score >= 0.95 AND action type is YAML, THE Decision_Gate SHALL approve the action
4. WHEN confidence_score < 0.95 AND action type is YAML, THE Decision_Gate SHALL reject the action
5. WHEN an action is rejected by confidence gating, THE Audit_Logger SHALL record the rejection with reason "confidence_too_low"

### Requirement 4: Conservative Action Routing

**User Story:** As a security operator, I want process termination limited to specific high-risk tactics, so that the system applies the most appropriate remediation method for each threat type.

#### Acceptance Criteria

1. WHEN mitre_techniques contains tactic "Execution", THE Routing_Engine SHALL select SIGKILL_Action
2. WHEN mitre_techniques contains tactic "Privilege Escalation", THE Routing_Engine SHALL select SIGKILL_Action
3. WHEN mitre_techniques contains tactic "Credential Access", THE Routing_Engine SHALL select SIGKILL_Action
4. WHEN mitre_techniques contains tactic "Persistence", THE Routing_Engine SHALL select YAML_Action
5. WHEN mitre_techniques contains tactic "Defense Evasion", THE Routing_Engine SHALL select YAML_Action
6. WHEN mitre_techniques contains multiple tactics, THE Routing_Engine SHALL prioritize SIGKILL_Action if any SIGKILL-eligible tactic is present
7. WHEN mitre_techniques contains no recognized tactics, THE Routing_Engine SHALL default to YAML_Action

### Requirement 5: Autonomy Mode Control

**User Story:** As a security administrator, I want configurable autonomy modes, so that I can control the level of human oversight required for remediation actions.

#### Acceptance Criteria

1. WHERE autonomy_mode == "autonomous", THE RemediationAgent SHALL execute approved actions without human confirmation
2. WHERE autonomy_mode == "tiered", THE RemediationAgent SHALL execute YAML_Action without confirmation AND require confirmation for SIGKILL_Action
3. WHERE autonomy_mode == "human-in-loop", THE RemediationAgent SHALL require human confirmation for all actions
4. WHEN human confirmation is required, THE RemediationAgent SHALL log the pending action and wait for external approval signal
5. WHEN autonomy_mode is not set, THE RemediationAgent SHALL default to "tiered" mode

### Requirement 6: SIGKILL Execution

**User Story:** As a security responder, I want the system to terminate malicious processes, so that active threats are immediately stopped.

#### Acceptance Criteria

1. WHEN executing SIGKILL_Action, THE Execution_Engine SHALL run kubectl exec <pod> -n <namespace> -- kill -9 <pid>
2. WHEN the target pod does not exist, THE Execution_Engine SHALL log an error and mark the action as failed
3. WHEN the target process does not exist, THE Execution_Engine SHALL log a warning and mark the action as succeeded
4. WHEN kubectl exec returns exit code 0, THE Execution_Engine SHALL mark the action as succeeded
5. WHEN kubectl exec returns non-zero exit code, THE Execution_Engine SHALL log the error and mark the action as failed
6. THE Execution_Engine SHALL extract pod, namespace, and pid from the event context before executing SIGKILL_Action

### Requirement 7: YAML Patch Execution

**User Story:** As a security engineer, I want the system to apply Kubernetes resource patches, so that misconfigurations and policy violations are automatically corrected.

#### Acceptance Criteria

1. WHEN executing YAML_Action, THE Execution_Engine SHALL run kubectl apply -f <yaml_patch>
2. WHEN the yaml_patch field is empty or missing, THE Execution_Engine SHALL log an error and skip execution
3. WHEN kubectl apply returns exit code 0, THE Execution_Engine SHALL mark the action as succeeded
4. WHEN kubectl apply returns non-zero exit code, THE Execution_Engine SHALL log the error and mark the action as failed
5. THE Execution_Engine SHALL validate that yaml_patch contains valid YAML syntax before execution
6. WHEN YAML validation fails, THE Execution_Engine SHALL log an error and skip execution

### Requirement 8: Dry Run Mode

**User Story:** As a security operator, I want a dry run mode for safe testing, so that I can validate remediation logic without affecting production systems.

#### Acceptance Criteria

1. WHERE dry_run == True, THE Execution_Engine SHALL log the action that would be executed without running kubectl commands
2. WHERE dry_run == True, THE Audit_Logger SHALL record actions with status "dry_run"
3. WHERE dry_run == False, THE Execution_Engine SHALL execute kubectl commands normally
4. WHEN dry_run is not set, THE RemediationAgent SHALL default to dry_run == True
5. THE Config_Manager SHALL allow runtime toggling of dry_run mode via configuration endpoint

### Requirement 9: Kubernetes Authentication

**User Story:** As a platform engineer, I want flexible Kubernetes authentication, so that the agent can run both in-cluster and externally.

#### Acceptance Criteria

1. WHEN running in-cluster, THE Execution_Engine SHALL authenticate using ServiceAccount credentials from /var/run/secrets/kubernetes.io/serviceaccount/token
2. WHEN running externally, THE Execution_Engine SHALL authenticate using kubeconfig file specified in configuration
3. WHEN ServiceAccount authentication fails, THE Execution_Engine SHALL log an error and mark actions as failed
4. WHEN kubeconfig authentication fails, THE Execution_Engine SHALL log an error and mark actions as failed
5. THE Config_Manager SHALL detect in-cluster vs external deployment automatically based on environment

### Requirement 10: Audit Trail Logging

**User Story:** As a compliance officer, I want comprehensive audit logs of all remediation actions, so that I can review security responses and demonstrate compliance.

#### Acceptance Criteria

1. WHEN RemediationAgent processes an event, THE Audit_Logger SHALL create an audit record keyed by event_id
2. THE Audit_Logger SHALL record timestamp, event_id, action_type, confidence_score, autonomy_mode, and execution_status for every action
3. WHEN an action is rejected by Decision_Gate, THE Audit_Logger SHALL record the rejection reason
4. WHEN an action fails during execution, THE Audit_Logger SHALL record the error message and stack trace
5. THE Audit_Logger SHALL persist audit records to Redis_Store with TTL of 90 days
6. THE Audit_Logger SHALL support querying audit records by event_id, timestamp range, and execution_status

### Requirement 11: Configuration Management

**User Story:** As a security administrator, I want runtime configuration updates, so that I can adjust remediation behavior without redeploying the system.

#### Acceptance Criteria

1. THE Config_Manager SHALL load configuration from environment variables on startup
2. THE Config_Manager SHALL expose a REST API endpoint for runtime configuration updates
3. WHEN configuration is updated via API, THE Config_Manager SHALL validate the new configuration before applying
4. WHEN configuration validation fails, THE Config_Manager SHALL reject the update and return an error response
5. THE Config_Manager SHALL support updating autonomy_mode, dry_run, confidence_thresholds, and tactic_routing without restart
6. THE Config_Manager SHALL log all configuration changes to the audit trail

### Requirement 12: Error Handling and Recovery

**User Story:** As a system operator, I want robust error handling, so that transient failures don't prevent future remediation actions.

#### Acceptance Criteria

1. WHEN kubectl commands timeout, THE Execution_Engine SHALL retry up to 3 times with exponential backoff
2. WHEN Redis_Store is unavailable, THE Audit_Logger SHALL buffer audit records in memory and retry persistence
3. WHEN the configuration endpoint is unreachable, THE Config_Manager SHALL continue using cached configuration
4. WHEN an unhandled exception occurs, THE RemediationAgent SHALL log the error and return control to LangGraph without crashing
5. THE RemediationAgent SHALL implement circuit breaker pattern for Kubernetes API calls with 5-minute cooldown after 10 consecutive failures

### Requirement 13: Performance and Scalability

**User Story:** As a platform engineer, I want efficient remediation processing, so that the system can handle high event volumes without bottlenecks.

#### Acceptance Criteria

1. THE RemediationAgent SHALL process each event in less than 5 seconds under normal conditions
2. THE RemediationAgent SHALL support concurrent processing of up to 100 events per minute
3. WHEN event processing exceeds 5 seconds, THE RemediationAgent SHALL log a performance warning
4. THE Audit_Logger SHALL batch Redis writes in groups of 10 records or 1-second intervals, whichever comes first
5. THE Config_Manager SHALL cache configuration in memory and refresh every 60 seconds

### Requirement 14: Observability and Monitoring

**User Story:** As a site reliability engineer, I want metrics and health checks, so that I can monitor remediation agent health and performance.

#### Acceptance Criteria

1. THE RemediationAgent SHALL expose Prometheus metrics for actions_total, actions_succeeded, actions_failed, and processing_duration_seconds
2. THE RemediationAgent SHALL expose a /health endpoint returning 200 OK when all dependencies are reachable
3. WHEN Kubernetes API is unreachable, THE health endpoint SHALL return 503 Service Unavailable
4. WHEN Redis_Store is unreachable, THE health endpoint SHALL return 503 Service Unavailable
5. THE RemediationAgent SHALL log structured JSON logs with level, timestamp, event_id, and message fields

### Requirement 15: Security and Least Privilege

**User Story:** As a security architect, I want minimal required permissions, so that a compromised remediation agent has limited blast radius.

#### Acceptance Criteria

1. WHEN running in-cluster, THE ServiceAccount SHALL have RBAC permissions limited to pods/exec and configmaps/apply in monitored namespaces only
2. THE ServiceAccount SHALL NOT have cluster-admin or namespace-admin roles
3. THE ServiceAccount SHALL NOT have permissions to delete resources
4. WHEN kubeconfig is used, THE Config_Manager SHALL validate that credentials have appropriate scope limitations
5. THE RemediationAgent SHALL refuse to start if ServiceAccount has overly permissive roles

### Requirement 16: State Management

**User Story:** As a LangGraph developer, I want proper state handling, so that the remediation node integrates correctly with the orchestration framework.

#### Acceptance Criteria

1. THE RemediationAgent SHALL accept a state dictionary as input containing all upstream node outputs
2. THE RemediationAgent SHALL add remediation_status, remediation_action, and remediation_timestamp fields to the state dictionary
3. THE RemediationAgent SHALL return the updated state dictionary to LangGraph
4. WHEN remediation is skipped, THE RemediationAgent SHALL set remediation_status to "skipped" with reason
5. THE RemediationAgent SHALL preserve all existing state fields without modification

### Requirement 17: MITRE ATT&CK Integration

**User Story:** As a threat analyst, I want remediation decisions based on MITRE tactics, so that responses align with threat intelligence frameworks.

#### Acceptance Criteria

1. THE Routing_Engine SHALL parse mitre_techniques field as a list of tactic strings
2. THE Routing_Engine SHALL recognize all 14 MITRE ATT&CK tactics from the framework
3. WHEN mitre_techniques contains unrecognized tactics, THE Routing_Engine SHALL log a warning and continue processing
4. THE Audit_Logger SHALL record the full list of mitre_techniques for each processed event
5. THE RemediationAgent SHALL support future extension of tactic-to-action mappings via configuration

### Requirement 18: Idempotency

**User Story:** As a system architect, I want idempotent remediation actions, so that duplicate event processing doesn't cause unintended side effects.

#### Acceptance Criteria

1. WHEN processing an event_id that was already remediated, THE RemediationAgent SHALL check the audit trail before executing
2. WHEN an event_id has a successful remediation record within 5 minutes, THE RemediationAgent SHALL skip re-execution
3. WHEN an event_id has a failed remediation record, THE RemediationAgent SHALL allow retry after 1 minute
4. THE Audit_Logger SHALL record duplicate event attempts with status "duplicate_skipped"
5. THE RemediationAgent SHALL use Redis_Store for distributed idempotency checks across multiple agent instances
