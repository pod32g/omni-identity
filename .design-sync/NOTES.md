# design-sync notes — @omni-identity/ui

First sync: 2026-06-19. Shape: storybook. 14 component cards synced; all graded
`match` on the first pass.

## How it's wired

- **Package** is the `design-system/` subpackage. The converter runs from the
  repo root with `--entry design-system/dist/index.js` (the package isn't in
  `node_modules` in its own source repo) and `--node-modules design-system/node_modules`.
- **CSS** ships as a separate compiled file: `cfg.cssEntry: "dist/index.css"`
  (resolved relative to the package dir). Build the library first
  (`buildCmd` = `npm --prefix design-system run build`) so `dist/index.css` exists.
- **Dark canvas via provider.** Omni Identity is a dark theme. The card template
  hard-codes a white body, so light-on-transparent components were unreadable.
  Fix: a `ThemeProvider` component (dark surface) set as `cfg.provider`, and used
  as the Storybook decorator (`.storybook/preview.tsx`) so both sides wrap
  identically. `ThemeProvider` is a bundle export but has no card (`titleMap` null).
- **Excluded cards** (`titleMap` null): `LoginForm`, `SetupForm` (app-specific
  screens, out of scope), `ThemeProvider` (it's the provider).
- **`cardMode: "column"`** for `Alert`, `AdminNav`, `Field`, `Input` — their
  stories are wider than a grid cell.

## Re-sync risks (watch these)

- **Provider/decorator must stay in lockstep.** If `cfg.provider` (ThemeProvider)
  and the `.storybook/preview.tsx` decorator diverge, previews and the reference
  will wrap differently and grades will be wrong. Change both together.
- **`cssEntry` depends on the build.** If `dist/index.css` is stale or the tsup
  CSS output path changes, previews render unstyled. The buildCmd guards this.
- **Grades assume the dark surface.** All `match` verdicts were made with the
  ThemeProvider surface. Removing/altering it silently regresses every preview —
  scoped-compare a text-heavy component (e.g. Table) after any provider change.
- **Story coverage is shallow by design** — each component has 1–3 stories
  covering the real variants; no story caps were hit.
