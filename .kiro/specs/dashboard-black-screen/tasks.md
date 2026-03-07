# Implementation Plan

- [-] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - CommandCenter Renders Successfully
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists (ReferenceError: useState is not defined)
  - **Scoped PBT Approach**: Scope the property to the concrete failing case - CommandCenter component render attempts
  - Test that CommandCenter component renders without runtime errors when useState is properly imported
  - Verify component mounts successfully and dashboard UI is visible
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS with ReferenceError (this is correct - it proves the bug exists)
  - Document counterexamples found: "CommandCenter fails to render, useState is not defined, black screen displayed"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 2.1, 2.2, 2.3_

- [~] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Other Components and Functionality
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for components and functionality NOT affected by CommandCenter import
  - Write property-based tests capturing observed behavior patterns:
    - Other components (Header, Sidebar, IncidentLedger, ForensicsPanel, SyscallTicker) render correctly in isolation
    - API connections to http://localhost:8081 work through Vite proxy
    - Store data fetching from API endpoints populates state correctly
    - CSS styling with dark theme, colors, and layout remain unchanged
  - Property-based testing generates many test cases for stronger guarantees
  - Run tests on UNFIXED code (test components in isolation if CommandCenter blocks full app)
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [ ] 3. Fix for missing useState import in CommandCenter

  - [~] 3.1 Implement the fix
    - Open src/components/CommandCenter.jsx
    - Locate the React import statement at the top of the file
    - Add useState to the import statement:
      - If file has `import React from 'react'`: Change to `import React, { useState } from 'react'`
      - If file has `import { ... } from 'react'`: Add `useState` to the destructured imports
      - If file has no React import: Add `import { useState } from 'react'`
    - Verify no other React hooks are used without being imported
    - Do not modify any component logic, JSX, or functionality
    - _Bug_Condition: isBugCondition(input) where input.component == 'CommandCenter' AND usesReactHook(input.component, 'useState') AND NOT hasImport(input.component, 'useState', 'react')_
    - _Expected_Behavior: CommandCenter renders successfully without runtime errors, dashboard UI is visible_
    - _Preservation: All other components, API connections, state management, and styling remain unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4_

  - [~] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - CommandCenter Renders Successfully
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - Verify CommandCenter mounts without errors
    - Verify dashboard UI is visible in browser
    - Verify no console errors related to useState
    - _Requirements: 2.1, 2.2, 2.3_

  - [~] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Other Components and Functionality
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all other components render correctly
    - Confirm API connections continue to work
    - Confirm state management and styling are unchanged
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [~] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
