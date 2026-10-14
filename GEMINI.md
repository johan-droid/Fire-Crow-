# Fire Crow Workspace Rules

## UI Building & Frontend Design Standards

### Default Creative MCP: Google Stitch (`stitch`)

Google Stitch MCP (`stitch`) is officially designated as the **default creative MCP for building UI** across this entire workspace.

Whenever building, designing, generating, refactoring, or updating any user interfaces, frontend screens, components, layout systems, or visual styling:

1. **Mandatory Creative Engine**:
   - Always route all creative UI generation, screen building, and design workflows through **Stitch MCP** (`stitch`).
   - Use `generate_screen_from_text` to generate visual UI screens directly from creative briefs, user requirements, or prompt descriptions.
   - Use `generate_variants` to explore alternative visual compositions, component hierarchy variations, and layout themes.
   - Use `edit_screens` for targeted iterative edits and design polishing.
   - Use `get_screen` to inspect the generated HTML, CSS, component regions, and layout tree.

2. **Design System & Token Consistency**:
   - Manage global design tokens (typography, color palettes, spacing, elevation) via Stitch design system tools: `list_design_systems`, `create_design_system_from_design_md`, and `apply_design_system`.
   - Never generate or hardcode ad-hoc visual styling, custom color palettes, or uncoordinated layouts without synchronizing with Stitch.

3. **Frontend Code Implementation**:
   - Derive and translate Stitch visual design specifications directly into production React + TypeScript + Tailwind CSS code under `frontend/src/`.
   - Maintain exact spacing scales, responsive breakpoints, and interaction models matching the creative output from Stitch.
