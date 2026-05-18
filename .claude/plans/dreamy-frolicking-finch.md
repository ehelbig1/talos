# Implementation Plan: Platform Hardening & UI Restoration

## Context
This plan addresses several key areas identified for improvement in the Talos platform:
1.  **UI Consistency**: The `category` field was previously removed from GraphQL queries, causing visual inconsistencies in the workflow editor.
2.  **WASM Security**: Resource limiting in the WASM runtime is being hardened by making table size limits configurable via environment variables, rather than being hard-coded.
3.  **Code Maintenance**: Dead code in the frontend `Workspace` component is being removed to improve maintainability.
4.  **CI/CD Efficiency**: The CI pipeline is being optimized by parallelizing frontend and backend test jobs to reduce total build time.

## Implementation Steps

### 1. Restore UI Consistency (WasmModule category)
Restore the `category` field to `WasmModule` and ensure it flows from the database to the frontend.

- **Backend (Registry)**: Update `WasmModule` struct in `controller/src/registry/mod.rs` to include `pub category: Option<String>` and fetch it in `get_module`.
- **Backend (Schema)**:
    - Update `WasmModule` struct in `controller/src/api/schema.rs` to include `pub category: Option<String>`.
    - Update `ModuleLoader` in `controller/src/api/schema.rs` to select `category` in its SQL query and map it to the struct.
- **Frontend (Queries)**:
    - Update `WasmModule` interface and `GetModules` query in `frontend/src/lib/workflowLoader.ts` to include `category`.
    - Update `WasmModule` interface and `myModules` query in `frontend/src/hooks/useAddExistingNode.ts` to include `category`.

### 2. Hardened WASM Resource Limiting
Make WASM table size limits configurable and enforce them in the runtime.

- **Context Update**: Update `TalosContext` in `worker/src/context.rs`:
    - Add `pub max_table_size: usize` to `TalosContext` struct.
    - Update `TalosContext::new` signature and implementation to initialize this field.
    - Replace hard-coded `10_000` in `ResourceLimiter::table_growing` with `self.max_table_size`.
- **Runtime Update**: Update `TalosRuntime` in `worker/src/runtime.rs`:
    - Read `WASM_MAX_TABLE_SIZE` from environment in `TalosRuntime::new` (default to `10_000`).
    - Store it in `TalosRuntime` and pass it to `TalosContext::new` in `execute_job_with_context_and_timeout_internal`.

### 3. Frontend Clean-up
- **File**: `frontend/src/components/Workspace.tsx`
- Remove the dead code block `{false && ...}` (lines 193-203) and the unused `toolboxWidth` calculation.

### 4. CI/CD Optimization
- **File**: `.github/workflows/ci.yml`
- Split `build-and-test` into parallel `backend-tests` and `frontend-tests` jobs.
- Both jobs should use `actions/checkout`.
- `backend-tests` handles Rust toolchain, cargo caching, audit, and Rust tests.
- `frontend-tests` handles Node setup, npm install, and frontend unit/E2E tests.
- Add a `build-docker` job that `needs: [backend-tests, frontend-tests]` to ensure production builds only happen on green tests.

## Critical Files
- `controller/src/api/schema.rs`
- `worker/src/context.rs`
- `worker/src/runtime.rs`
- `frontend/src/lib/workflowLoader.ts`
- `frontend/src/hooks/useAddExistingNode.ts`
- `.github/workflows/ci.yml`

## Verification Section
1. **UI Check**: Open the workflow editor and verify that node icons (categories) are correctly displayed.
2. **WASM Security**: Run a test job and verify it still executes correctly with the default table limit.
3. **CI/CD**: Push the changes and verify that the GitHub Actions workflow runs in parallel and completes successfully.
4. **Integration Tests**: Run `cargo test` to ensure no regressions in existing security/concurrency tests.
