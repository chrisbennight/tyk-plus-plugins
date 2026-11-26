# Design and visual identity

The visual identity for **Tyk Plus Plugins** uses clear geometry, rounded strokes, open circular boundaries, and high-contrast light and dark surfaces. It makes the gateway's documentation and the [drift review dashboard](../admin/README.md) recognizable while keeping operational controls and security diffs easy to read.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="branding/assets/wordmark-on-dark.svg">
  <img src="branding/assets/wordmark-on-light.svg" width="320" alt="Tyk Plus">
</picture>

## Identity

The brand symbol ("The Checkpointed Gate") is a routed path entering an open ring from a hollow caller node, passing through a T-shaped gate and checkpoint junction, and emerging at an accented endpoint.

- **Canvas and stroke:** `128 × 128` grid with a 5-unit rounded stroke (`stroke-linecap="round"`, `stroke-linejoin="round"`). Connecting routes in relationship artwork use a finer 2.2-unit stroke.
- **Clear space:** Keep at least one endpoint diameter of clear space around the symbol. Use the symbol alone for browser tab icons and compact headers, and the wordmark or relationship header at the top of top-level documentation.
- **Portable vector lettering:** All SVG wordmark and header labels (`TYK PLUS`, `CLIENTS`, `CEDAR`, `DRIFT`, `SANDBOX`) are drawn as vector paths with `aria-label` attributes so rendering never depends on installed host fonts or external font services.
- **Relationship artwork:** The header illustration (`CLIENTS → TYK PLUS → CEDAR, DRIFT, SANDBOX`) introduces the gateway's role at a glance. Architectural and protocol diagrams in documentation remain separately editable Markdown or Mermaid diagrams.

## Typography

- **Body and controls:** `system-ui, sans-serif` at `16px` (`1.5` line height) for comfortable reading across operating systems with zero external network requests.
- **Code, fingerprints, and diffs:** `ui-monospace, monospace` at `0.9rem` for tool definitions, SHA-256 fingerprints, Cedar rules, and word-level diffs.
- **Headings:** Sentence case with standard spacing. Reserve wide uppercase lettering for the vector wordmark and diagram node labels.

## Color and surfaces

The artwork and the drift review dashboard ([`admin/static/style.css`](../admin/static/style.css)) share one theme-aware palette across light and `prefers-color-scheme: dark` modes:

| Role | CSS token | Light | Dark | Use |
| --- | --- | --- | --- | --- |
| Surface | `--bg` | `#ffffff` (`#f8f9fa` in header art) | `#15181b` | Page and card backgrounds |
| Ink | `--fg` | `#1d2125` | `#e6e9ec` | Primary text and symbol strokes |
| Muted text | `--muted` | `#5b636b` | `#a3abb3` | Metadata labels, breadcrumbs, operator identity |
| Hairline | `--line` | `#d5d9dd` | `#353b41` | Table borders, header rules, diff boxes |
| Brand & interactive accent | `--accent` | `#0b5cad` | `#7ab8ff` (`#1b4b8a` node fill) | Links, primary buttons, focus rings, brand endpoint nodes, routed connection lines |
| Warning & refused | `--warn`, `--warn-bg` | `#7a4b00` on `#fff4d6` | `#ffd27a` on `#3a2e12` | Drift warning banners, advisory flags, refused status |
| Diff removed | `--removed`, `--removed-mark` | `#ffebe9` / `#ffc1bc` | `#3d1f22` / `#7a2f35` | Removed lines and changed words in drift diffs |
| Diff added | `--added`, `--added-mark` | `#e6ffec` / `#abf2bc` | `#1b3524` / `#2f6b41` | Added lines and changed words in drift diffs |

**Brand accents are never status meanings.** Whether a tool is allowed by drift review, refused, or flagged for closer inspection must always be stated in words (and with `−` / `+` markers and screen-reader labels in diffs), never by color or brand decoration alone.

## Layout and accessibility

- **Strict self-containment:** The dashboard sends `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. Every stylesheet and icon must be embedded in the binary and served from the dashboard's own origin.
- **Keyboard and screen-reader navigation:** Interactive controls keep a visible `3px solid var(--accent)` focus outline. Diff rows include visible `−` and `+` markers paired with screen-reader text (`removed:` and `added:`), and changed words use `<mark>`.
- **Contrast and motion:** Text and interactive controls meet WCAG 2.2 AA contrast thresholds in both light and dark themes. Avoid animated GIFs or decorative motion in documentation and operational views.

## Brand assets

Editable vector sources live in [`docs/branding/`](branding/), with ready-to-use exports in [`docs/branding/assets/`](branding/assets/) and the embedded dashboard tab icon in [`admin/static/favicon.svg`](../admin/static/favicon.svg):

| Path | Purpose |
| --- | --- |
| [`docs/branding/symbol.svg`](branding/symbol.svg) | Canonical `128 × 128` vector symbol source |
| [`docs/branding/assets/symbol-on-light.svg`](branding/assets/symbol-on-light.svg), [`symbol-on-dark.svg`](branding/assets/symbol-on-dark.svg), [`symbol-mono.svg`](branding/assets/symbol-mono.svg) | Standalone brand symbol for light, dark, and monochrome contexts |
| [`docs/branding/assets/wordmark-on-light.svg`](branding/assets/wordmark-on-light.svg), [`wordmark-on-dark.svg`](branding/assets/wordmark-on-dark.svg) | Compact symbol and vector-outlined `TYK PLUS` wordmark |
| [`docs/branding/assets/header-light.svg`](branding/assets/header-light.svg), [`header-dark.svg`](branding/assets/header-dark.svg) | Theme-aware relationship header for [`README.md`](../README.md) |
| [`admin/static/favicon.svg`](../admin/static/favicon.svg) | Dark-tile tab icon embedded in and served by the drift review dashboard |
