import React from "react";
import "../../shared/auth.css";
import { Card } from "../Card/Card";
import { Alert } from "../Alert/Alert";
import { Field } from "../Field/Field";
import { Input } from "../Input/Input";
import { Button } from "../Button/Button";

export interface SetupFormProps {
  /** Error message shown above the form. */
  error?: string;
  /** Form POST target. */
  action?: string;
  onSubmit?: React.FormEventHandler<HTMLFormElement>;
}

/** The first-run wizard: create the first administrator account. */
export function SetupForm({ error, action, onSubmit }: SetupFormProps) {
  return (
    <Card variant="auth">
      <h1 className="omni-h1">Welcome to Omni Identity</h1>
      <p className="omni-muted">Create the first administrator account to get started.</p>
      {error ? <Alert>{error}</Alert> : null}
      <form className="omni-form" method="post" action={action} onSubmit={onSubmit}>
        <Field label="Username">
          <Input name="username" autoComplete="username" autoFocus required />
        </Field>
        <Field label="Email">
          <Input name="email" type="email" autoComplete="email" required />
        </Field>
        <Field label="Password">
          <Input
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={8}
            required
          />
        </Field>
        <Button type="submit">Create admin &amp; sign in</Button>
      </form>
    </Card>
  );
}
