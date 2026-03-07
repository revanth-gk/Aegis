# Implementation Plan

- [ ] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - All Generated Events Recorded
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate event loss in the pipeline
  - **Scoped PBT Approach**: Scope the property to concrete failing case: 5 attack commands generating ~10 events but only 1 recorded
  - Add instrumentation logging to each pipeline stage (stream reading, JSON parsing, event transformation, event recording)
  - Run start_app.sh on UNFIXED code and execute 5 attack commands (curl, cat /etc/shadow, nc, ps aux, nslookup)
  - Count events at each stage: stdin lines received, JSON parsed successfully, transform_event() returns (None vs valid), record_event() calls
  - Test that when Tetragon generates N >= 8 events, all N events are recorded in _recent_events and available via /api/events
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS - only 1 event recorded instead of ~10 (this is correct - it proves the bug exists)
  - Document counterexamples found: which stage drops events (likely transform_event() returning None for unrecognized event types)
  - Document which event types are being filtered vs. recorded
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Event Processing Behavior
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for the 1 event that is successfully recorded
  - Capture metrics updates: events_total increment, events_by_type, severity_breakdown, triage_breakdown
  - Capture SSE broadcasting: verify event is pushed to _sse_queues
  - Capture ML triage: verify triage and explanation fields are added
  - Capture Redis publishing: verify publisher.publish() is called
  - Write property-based tests capturing observed behavior patterns: for all successfully recorded events, metrics/SSE/triage/Redis processing must match observed behavior
  - Property-based testing generates many test cases for stronger guarantees across different event types and payloads
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 3. Fix for event generation issue

  - [ ] 3.1 Add diagnostic logging to identify dropped events
    - Add logger.debug() in transform_event() before returning None to log raw event keys
    - Add logger.debug() in process_line() to log when transform_event() returns None with full event JSON (truncated)
    - Add counter in api.py for filtered_events_total and increment when transform_event() returns None
    - Expose filtered_events_total in /api/metrics endpoint
    - Run pipeline and observe logs to identify which event types are being dropped
    - _Bug_Condition: isBugCondition(pipeline_state) where events_in_recent_events / tetragon_events_generated < 0.3_
    - _Expected_Behavior: All valid security events from Tetragon are recorded via record_event()_
    - _Preservation: Metrics tracking, SSE broadcasting, ML triage, Redis publishing must remain unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5_

  - [ ] 3.2 Expand event type recognition in transformer
    - Based on diagnostic logs, identify missing event types in _detect_event_type()
    - Add missing event types to the known_types list (e.g., process_kprobe variants, network events, file events)
    - Update transform_event() to handle new event types and map them to Sentinel schema
    - Ensure irrelevant event types still return None (preserve filtering behavior)
    - _Bug_Condition: isBugCondition(pipeline_state) where legitimate security events return None from transform_event()_
    - _Expected_Behavior: All valid security events are transformed and recorded_
    - _Preservation: Event transformation filtering logic for irrelevant events must remain unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1_

  - [ ] 3.3 Verify stream buffering and JSON parsing
    - Add logging to count stdin lines received in stream_from_stdin()
    - Add logging to count successful vs. failed JSON.loads() calls in process_line()
    - Verify that sys.stdin iteration is not batching events (should process line-by-line)
    - If buffering issues found, add flush() calls or adjust buffering settings
    - Improve JSON parsing error visibility by logging truncated line content on parse failures
    - _Bug_Condition: isBugCondition(pipeline_state) where stream buffering or JSON parsing drops events_
    - _Expected_Behavior: All valid JSON lines from kubectl logs are parsed and processed_
    - _Preservation: Error handling for malformed JSON (record_error() calls) must remain unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 3.5_

  - [ ] 3.4 Verify thread safety in record_event()
    - Add logging to track concurrent record_event() calls
    - Verify that _lock properly protects all _recent_events operations
    - Test with multiple concurrent events to ensure no race conditions
    - _Bug_Condition: isBugCondition(pipeline_state) where race conditions cause event loss_
    - _Expected_Behavior: All events are safely recorded in _recent_events without loss_
    - _Preservation: Thread safety and locking behavior must remain unchanged_
    - _Requirements: 2.4, 3.5_

  - [ ] 3.5 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - All Generated Events Recorded
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - Execute 5 attack commands and verify ~10 events are recorded in _recent_events
    - Verify /api/events returns all generated events
    - Verify event count ratio (recorded / generated) >= 0.8
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [ ] 3.6 Verify preservation tests still pass
    - **Property 2: Preservation** - Event Processing Behavior
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - Verify metrics updates (events_total, events_by_type, severity_breakdown, triage_breakdown) match observed behavior
    - Verify SSE broadcasting pushes events to _sse_queues with same structure
    - Verify ML triage adds triage and explanation fields with same logic
    - Verify Redis publishing calls publisher.publish() with same event structure
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Run full test suite including unit tests, property-based tests, and integration tests
  - Verify /api/events returns ~10 events after 5 attack commands
  - Verify /api/metrics shows events_total >= 8 and filtered_events_total is minimal
  - Verify SSE subscribers receive all events in real-time
  - Verify Redis receives all published events
  - Ensure all tests pass, ask the user if questions arise
