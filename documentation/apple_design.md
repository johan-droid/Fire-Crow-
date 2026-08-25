# Fire Crow — Apple Design System & Human Interface Guidelines

This design specification establishes the visual language, interaction patterns, component architecture, and aesthetic principles for the **Fire Crow** platform, inspired by Apple's Human Interface Guidelines (HIG) and Cupertino software design philosophy.

---

## 1. Core Design Philosophy

The Fire Crow interface is built on four core pillars:

1. **Clarity & Focus**: Minimalist layouts where critical security telemetry and vulnerability discoveries take primary hierarchy without visual clutter.
2. **Deference**: The interface defers to the content. Subtle translucent layers, hairline borders, and dark palettes keep the focus on code, attack topologies, and remediation diffs.
3. **Depth & Hierarchy**: Use of physical depth through multi-layer frosted glassmorphism (`backdrop-filter: blur(24px)`), soft atmospheric glows, and layered cards.
4. **Fluid Motion & Precision**: Intentional micro-interactions with Apple-standard easing curves (`cubic-bezier(0.16, 1, 0.3, 1)`), providing tactile and responsive feedback.

---

## 2. Color Palette & Glass Tokens

### Neutral Palette (Deep Space Gray / Onyx)
- **Canvas Base**: `#000000` (Pure Black) & `#070709` (Onyx Gray)
- **Primary Glass Surface**: `rgba(255, 255, 255, 0.035)`
- **Elevated Glass Surface**: `rgba(255, 255, 255, 0.06)`
- **Hover Glass Surface**: `rgba(255, 255, 255, 0.09)`
- **Hairline Specular Border**: `rgba(255, 255, 255, 0.08)`
- **Active Border**: `rgba(255, 255, 255, 0.2)`

### Apple Semantic Accent Palette
- **Fire Crow Amber (Primary Accent)**: `#ff6b00` / `#ff8533` (Dynamic energy & security intelligence)
- **Cupertino Blue**: `#0071e3` / `#2997ff` (Trust, identity, and navigation)
- **Mint Green (Success / Verified)**: `#30d158` / `#34c759` (Zero vulnerabilities, verified build)
- **Crimson Red (Critical Risk)**: `#ff453a` / `#ff3b30` (Exploit detected, CVE alerts)
- **Cyber Violet (AI Reasoning)**: `#bf5af2` / `#af52de` (Gemini Agentic loops)
- **System Yellow (Warning)**: `#ffd60a` / `#ffcc00` (Medium severity, pending approvals)

### Typography Colors
- **Headline Primary**: `#ffffff`
- **Gradient Headline Mask**: `linear-gradient(180deg, #ffffff 0%, rgba(255, 255, 255, 0.72) 100%)`
- **Secondary Body Text**: `#a1a1a6` (Apple space gray text)
- **Muted Subtext**: `#6e6e73`
- **Mono Accent**: `#e5e5ea`

---

## 3. Typography Scale & System

Fire Crow employs Apple's typography scale using `SF Pro Display`, `SF Pro Text`, and `Inter` with `JetBrains Mono` for code & telemetry.

| Style | Size | Weight | Tracking | Line Height |
| :--- | :--- | :--- | :--- | :--- |
| **Large Display (Hero)** | 3.5rem – 5.0rem (clamp) | 800 (Bold / Heavy) | `-0.04em` | `1.05` |
| **Section Title (H2)** | 2.25rem – 2.75rem | 700 (Bold) | `-0.03em` | `1.15` |
| **Card Header (H3)** | 1.25rem – 1.45rem | 600 (Semibold) | `-0.02em` | `1.25` |
| **Subheading / Lead** | 1.05rem – 1.2rem | 400 (Regular) | `-0.01em` | `1.6` |
| **Body Text** | 0.9rem – 0.95rem | 400 (Regular) | `0em` | `1.6` |
| **Footnote / Caption**| 0.75rem – 0.8rem | 500 (Medium) | `0.02em` | `1.4` |
| **Monospace Telemetry**| 0.75rem – 0.85rem | 500 / 600 | `0.01em` | `1.7` |

---

## 4. Component Design Specifications

### 4.1 Apple Frosted Glass Navigation Bar
- Height: `60px`
- Position: Sticky (`top: 0`, `z-index: 50`)
- Backdrop: `rgba(0, 0, 0, 0.65)` with `backdrop-filter: blur(20px) saturate(180%)`
- Bottom Border: `1px solid rgba(255, 255, 255, 0.08)`
- Interaction: Smooth transition on scroll with subtle drop-shadow.

### 4.2 Hero Eyebrow Pill Badge
- Pill radius: `9999px`
- Background: `rgba(255, 255, 255, 0.04)` with `1px solid rgba(255, 255, 255, 0.12)`
- Status Beacon: Pulsing `6px` circular indicator with glowing drop-shadow.
- Typography: Uppercase monospace `0.72rem`, `letter-spacing: 0.06em`.

### 4.3 Action Buttons
- **Cupertino Solid (Primary)**:
  - Background: `#ffffff`
  - Text Color: `#000000`
  - Radius: `10px` / `9999px` (Pill variant)
  - Hover: `transform: scale(1.02) translateY(-1px)`, slight brightness increase.
  - Active: `transform: scale(0.98)`
- **Frosted Glass Outline (Secondary)**:
  - Background: `rgba(255, 255, 255, 0.05)`
  - Border: `1px solid rgba(255, 255, 255, 0.15)`
  - Text Color: `#f5f5f7`
  - Hover: `background: rgba(255, 255, 255, 0.1)`, `border-color: rgba(255, 255, 255, 0.3)`
- **Link Button**:
  - Color: `#2997ff` with smooth hover underline and arrow translation (`translateX(3px)`).

### 4.4 Apple Bento Grid
The Bento Grid displays platform capabilities in asymmetric, modular glass containers:
- **Card Radius**: `18px` – `22px`
- **Card Background**: `linear-gradient(135deg, rgba(255, 255, 255, 0.035) 0%, rgba(255, 255, 255, 0.01) 100%)`
- **Card Border**: `1px solid rgba(255, 255, 255, 0.08)`
- **Hover Effect**: Subtle ambient radial highlight tracking, `border-color: rgba(255, 255, 255, 0.22)`, `transform: translateY(-3px)`.
- **Card Content**: High-contrast icon badge, bold title, concise description, and embedded interactive visualization widgets (e.g. animated graph, live latency meter, sandbox container locks).

### 4.5 Interactive Preview & Terminal Showcase
- **Window Controls**: Triple traffic light buttons (Red `#ff5f56`, Amber `#ffbd2e`, Green `#27c93f`) with subtle inset shine.
- **Segmented Control Tabs**: Cupertino capsule pill selector with animated sliding active indicator.
- **Views**:
  1. *Live Tokio Agent Stream*: Streaming log output with color-coded timestamps, phase names, and AST events.
  2. *Attack Topology Map*: Clean SVG node graph representing ingress points, vulnerability nodes, and target clusters.
  3. *AI Remediation Patch*: Side-by-side or unified diff block with green/red highlight lines and compiler verification badge.

### 4.6 Interactive Scan Playground
- **Repository Presets**: Capsule chips (`expressjs/express`, `tokio-rs/axum`, `fastapi`, `kubernetes`) for 1-click instant scans.
- **Scan Pipeline Bar**: Smooth animated percentage bar with dynamic phase descriptions (`Cloning AST`, `Gemini Agentic Reasoning`, `Docker Sandbox Execution`, `Verification Complete`).
- **Interactive Results Card**: Luminous discovery summary with direct CTA to launch the full console.

---

## 5. Animation & Motion Guidelines

All UI animations must adhere to Apple's fluid motion curve:

```css
/* Apple Natural Spring / Fluid Easing */
--apple-ease: cubic-bezier(0.16, 1, 0.3, 1);
--apple-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
--apple-duration-fast: 200ms;
--apple-duration-normal: 350ms;
--apple-duration-slow: 600ms;
```

---

## 6. Accessibility & Responsive Breakpoints

- **Desktop (>= 1200px)**: 3-column / 4-column Bento grid with full visual previews.
- **Tablet (768px – 1199px)**: 2-column adaptive layout, scaled terminal window.
- **Mobile (< 768px)**: 1-column stacked flow, horizontal scrollable preset chips, touch-friendly tap targets (`>= 44px`).
- **Contrast Ratios**: All text meets WCAG AA standards (>= 4.5:1 against deep dark backgrounds).
