# @omni-identity/ui

The Omni Identity dark-theme React component library — a faithful port of the
login + admin UI that ships as Go `html/template` in
`../internal/web/templates`. Built so the design can be synced to
claude.ai/design and reused 1:1 in code.

## Use

```tsx
import { PageShell, Card, Field, Input, Button, Alert } from "@omni-identity/ui";
import "@omni-identity/ui/styles.css";

<PageShell>
  <Card variant="auth">
    <Field label="Username"><Input name="username" /></Field>
    <Button type="submit">Sign in</Button>
  </Card>
</PageShell>;
```

## Styling idiom

Everything is plain CSS driven by **design tokens** — CSS custom properties in
[`src/tokens.css`](src/tokens.css), all prefixed `--omni-*` (e.g.
`--omni-bg`, `--omni-surface`, `--omni-accent`, `--omni-radius-card`). Components
use BEM-ish global classes (`omni-card`, `omni-btn--primary`, `omni-badge--ok`).
Never hard-code hex — reference a token.

## Components

Primitives: `Button`, `Input`, `Select`, `Textarea`, `Field`, `Checkbox`.
Feedback: `Alert`, `Callout`. Layout: `Card`, `PageShell`, `AdminNav`.
Data: `Table`, `Badge`, `Code`. Screens: `LoginForm`, `SetupForm`.

## Develop

```sh
npm install
npm run storybook        # interactive dev (http://localhost:6006)
npm test                 # Vitest render-smoke tests
npm run typecheck        # tsc --noEmit
npm run build            # tsup -> dist/ (ESM + CJS + .d.ts + index.css)
npm run build-storybook  # static Storybook (design-sync input)
```
