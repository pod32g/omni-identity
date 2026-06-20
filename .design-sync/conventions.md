## Building with Omni Identity UI

Omni Identity UI is a **dark-theme** React component library. Components are plain
React; styling is driven by **design tokens** (CSS custom properties named
`--omni-*`). There is no utility-class framework — compose the library components
and write your own layout glue with the tokens.

### Always wrap in `ThemeProvider`

Wrap every screen or region in `<ThemeProvider>`. It establishes the dark page
background (`--omni-bg`), the base text color (`--omni-text`), and the font.
Without it, components render dark-theme (light) text on no background and are
unreadable.

```tsx
import { ThemeProvider, Card, Field, Input, Button } from "@omni-identity/ui";
import "@omni-identity/ui/styles.css";

<ThemeProvider>
  <Card>
    <h2 style={{ margin: 0, color: "var(--omni-text)" }}>Settings</h2>
    <Field label="Issuer">
      <Input defaultValue="https://id.omni.local" />
    </Field>
    <Button>Save</Button>
  </Card>
</ThemeProvider>;
```

### Design tokens (use these for your own layout)

- Surfaces: `--omni-bg` (page), `--omni-surface` (cards), `--omni-surface-inset`
  (inputs), `--omni-border`, `--omni-border-strong`.
- Text: `--omni-text`, `--omni-text-dim`, `--omni-text-muted`.
- Accent / status: `--omni-accent` (primary action), `--omni-link`,
  `--omni-danger-text`, `--omni-ok-text`.
- Radii: `--omni-radius-card`, `--omni-radius-control`, `--omni-radius-pill`.
- Spacing: `--omni-space-1` … `--omni-space-7` (6–32px).
- Type: `--omni-font-body`, `--omni-font-size-base` / `-sm` / `-xs` / `-h1` / `-h2`.

Never hard-code hex — reference a token so the dark theme stays consistent.

### Components, not classes

Components apply their own global classes (`omni-card`, `omni-btn--primary`,
`omni-badge--ok`, `omni-field`, `omni-table`); you don't write these by hand.
Choose appearance through props: `Button variant="primary|secondary"`,
`Badge tone="ok|off"`, `Card variant="default|auth"`, `Alert tone="error|success"`.
`PageShell` is the full-height dark page; `AdminNav` is the admin top bar.

### Where the truth lives

The complete stylesheet — tokens plus every component class — is `styles.css`
(which imports `_ds_bundle.css`); read it before styling. Each component's exact
API is in its `<Name>.d.ts`, and usage notes are in its `<Name>.prompt.md`.
