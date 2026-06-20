# Omni Identity UI — Component Library Design Spec

Date: 2026-06-19
Status: Approved (build approved via "implement this")

## Goal

Extract Omni Identity's existing dark-theme login/admin UI (currently Go
`html/template` with inline CSS in `internal/web/templates/base.html`) into a
real **React + TypeScript component library**, so it can be synced to
claude.ai/design and the design agent builds with the actual Omni Identity
components. This is a faithful **port** of the existing look, not a redesign.

## Decisions

| Decision | Choice |
|----------|--------|
| Scope | Full set (~16 components covering every template) |
| Storybook | Yes (Storybook 8, Vite builder) — best design-sync fidelity |
| Location | `design-system/` subfolder in the omni-identity repo |
| Styling | Plain CSS + CSS-custom-property tokens (`var(--omni-*)`) — faithful port, enumerable vocabulary |
| Build | tsup → `dist/` (ESM + CJS + `.d.ts`); global bundle name `OmniIdentityUI` |
| Tests | Vitest + Testing Library render-smoke per component |
| Package manager | npm (package-lock.json) |
| Framework | React 18 + TypeScript |

Rejected: CSS Modules (hashed classes aren't enumerable for the conventions
header), Tailwind/styled-components (a rewrite, not a port).

## Layout

```
design-system/
├── package.json            # @omni-identity/ui, scripts, deps
├── tsconfig.json  tsup.config.ts  vitest.config.ts
├── .storybook/main.ts  preview.ts
├── src/
│   ├── tokens.css          # CSS custom properties from base.html
│   ├── index.ts            # barrel export (drives window.OmniIdentityUI.*)
│   └── components/<Name>/
│       ├── <Name>.tsx  <Name>.css  <Name>.stories.tsx  <Name>.test.tsx
└── dist/                   # tsup output (gitignored)
```

`design-system/{node_modules,dist,storybook-static}` added to repo `.gitignore`.

## Design tokens (`src/tokens.css`)

CSS custom properties extracted verbatim from `base.html`:

- Colors: `--omni-bg #0f1115`, `--omni-surface #171a21`, `--omni-surface-inset #0f1115`,
  `--omni-border #262b36`, `--omni-border-strong #2c3340`, `--omni-text #e7e9ee`,
  `--omni-text-muted #97a0b0`, `--omni-text-dim #b6bdca`, `--omni-accent #4d7cff`,
  `--omni-accent-hover #3d6cf0`, `--omni-danger-bg #3a1b1f`, `--omni-danger-border #6e2a31`,
  `--omni-danger-text #ffb4bb`, `--omni-ok-bg #143524`, `--omni-ok-text #7ee2a8`,
  `--omni-link #7aa2ff`
- Radii: `--omni-radius-card 14px`, `--omni-radius-control 8px`, `--omni-radius-pill 999px`
- Spacing scale, type scale, font stack, card shadow

Every component styles via tokens only — never raw hex.

## Component inventory (~16)

- **Primitives:** `Button` (variant primary|secondary), `Input`, `Select`,
  `Textarea`, `Field` (label + control + optional error), `Checkbox`
- **Feedback:** `Alert` (tone error|success), `Callout` (one-time secret notice)
- **Layout:** `Card` (variant default|auth), `PageShell`, `AdminNav`
- **Data:** `Table`, `Badge` (tone ok|off), `Code`
- **Composed:** `LoginForm`, `SetupForm`

Props mirror the templates' real usage. Each component: typed props, colocated
CSS using tokens, a Storybook story (the design-sync preview source), and a
Vitest smoke test.

## Testing & verification

- Vitest render-smoke per component (renders without crashing; applies the
  expected root class / token-driven style).
- Storybook stories as the visual surface.
- Final fidelity gate: design-sync screenshot grading during the sync.

## Success criteria

- `npm run build` emits `dist/` (ESM+CJS+types); `npm test` green;
  `npm run build-storybook` succeeds.
- Library visually matches the existing templates (same dark theme).
- `/design-sync` detects the Storybook, verifies each component, and uploads to
  a new claude.ai/design project.

## Non-goals

- No redesign / new visual language.
- No backend changes — the Go templates stay as the running UI; this library is
  the design-system artifact.
- No publishing to npm.
