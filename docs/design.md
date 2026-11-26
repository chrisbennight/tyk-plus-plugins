# Design and visual identity

The visual identity for Tyk Plus Plugins uses rounded strokes, open circular boundaries, and high-contrast light and dark surfaces across the documentation and the [drift review dashboard](../admin/README.md).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="branding/assets/wordmark-on-dark.svg">
  <img src="branding/assets/wordmark-on-light.svg" width="320" alt="Tyk Plus">
</picture>

## Identity

The symbol is a routed path entering an open ring from a hollow caller node, passing through a T-shaped gate and checkpoint junction, and ending at an accented node. It uses a 5-unit rounded stroke on a `128 × 128` canvas; connecting routes in the header diagram use a 2.2-unit stroke. Keep at least one endpoint diameter of clear space around the mark.

Use the symbol alone for browser tab icons and compact headers, and the wordmark or relationship header at the top of top-level documentation. All lettering in the SVG files (`TYK PLUS`, `CLIENTS`, `CEDAR`, `DRIFT`, `SANDBOX`) is drawn as vector path outlines with `aria-label` attributes so rendering does not depend on installed host fonts. The header diagram (`CLIENTS → TYK PLUS → CEDAR, DRIFT, SANDBOX`) is an introduction to the project; technical diagrams in the documentation stay in editable Markdown or Mermaid.

## Typography

Body text and controls use `system-ui, sans-serif` at `16px` with a `1.5` line height. Tool definitions, SHA-256 fingerprints, Cedar rules, and diffs use `ui-monospace, monospace` at `0.9rem`. Headings use sentence case and normal spacing; wide uppercase lettering is reserved for the SVG wordmark and diagram node labels.

## Color and surfaces

The SVG artwork and the drift review dashboard ([`admin/static/style.css`](../admin/static/style.css)) share one light and dark (`prefers-color-scheme: dark`) palette:

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

Brand accents never carry status meanings. Whether a tool is allowed by drift review, refused, or flagged for inspection is always stated in words (and with `−` / `+` markers and screen-reader labels in diffs), never by color or brand decoration alone.

## Layout and accessibility

The dashboard sets `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, so every stylesheet and icon is embedded in the binary and served from the dashboard's own origin. Interactive controls keep a `3px solid var(--accent)` focus outline, diff rows include visible `−` and `+` markers with screen-reader text (`removed:` and `added:`) and `<mark>` around changed words, and text and controls meet WCAG 2.2 AA contrast thresholds in both themes. Avoid animated images or decorative motion in documentation and operational views.

## Brand assets

| Path | Purpose |
| --- | --- |
| [`docs/branding/symbol.svg`](branding/symbol.svg) | Canonical `128 × 128` vector symbol source |
| [`docs/branding/assets/symbol-on-light.svg`](branding/assets/symbol-on-light.svg), [`symbol-on-dark.svg`](branding/assets/symbol-on-dark.svg), [`symbol-mono.svg`](branding/assets/symbol-mono.svg) | Standalone brand symbol for light, dark, and monochrome contexts |
| [`docs/branding/assets/wordmark-on-light.svg`](branding/assets/wordmark-on-light.svg), [`wordmark-on-dark.svg`](branding/assets/wordmark-on-dark.svg) | Compact symbol and vector-outlined `TYK PLUS` wordmark |
| [`docs/branding/assets/header-light.svg`](branding/assets/header-light.svg), [`header-dark.svg`](branding/assets/header-dark.svg) | Theme-aware relationship header for [`README.md`](../README.md) |
| [`admin/static/favicon.svg`](../admin/static/favicon.svg) | Dark-tile tab icon embedded in and served by the drift review dashboard |
