---
name: firecrow_mcp_validator
description: Automatically triggers the custom Fire Crow MCP Build & Test Validator script to verify Rust backend compilation, test checks, TypeScript types, and Vite frontend builds whenever project code changes are made.
---

# Fire Crow Custom MCP Build & Test Validator Skill

Use this skill whenever code updates, refactorings, database migrations, or feature additions are completed in the Fire Crow repository.

## Execution Instruction

Run the custom MCP validator script from the workspace root:

```bash
python3 backend/scripts/mcp_firecrow_validator.py --validate
```

Or for raw JSON output:

```bash
python3 backend/scripts/mcp_firecrow_validator.py --json
```

## Validation Checklist Performed by Custom MCP
1. **Rust Backend Check (`cargo check`)**: Ensures zero compilation or syntax errors in backend crates.
2. **Rust Backend Test Build (`cargo test --no-run`)**: Ensures all unit and integration test signatures compile cleanly.
3. **Frontend Type Check (`npx tsc --noEmit`)**: Validates strict TypeScript compilation without type errors.
4. **Frontend Production Build (`npm run build`)**: Verifies Vite bundle creation and asset linking.
