import React from "react";
import "../../shared/auth.css";
import { Card } from "../Card/Card";
import { Alert } from "../Alert/Alert";
import { Field } from "../Field/Field";
import { Input } from "../Input/Input";
import { Button } from "../Button/Button";

export interface LoginFormProps {
  /** Error message shown above the form (e.g. bad credentials). */
  error?: string;
  /** Form POST target. */
  action?: string;
  onSubmit?: React.FormEventHandler<HTMLFormElement>;
}

/** The sign-in screen: an auth Card composing Field + Input + Button. */
export function LoginForm({ error, action, onSubmit }: LoginFormProps) {
  return (
    <Card variant="auth">
      <h1 className="omni-h1">Omni Identity</h1>
      <p className="omni-muted">Sign in to continue.</p>
      {error ? <Alert>{error}</Alert> : null}
      <form className="omni-form" method="post" action={action} onSubmit={onSubmit}>
        <Field label="Username">
          <Input name="username" autoComplete="username" autoFocus required />
        </Field>
        <Field label="Password">
          <Input
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </Field>
        <Button type="submit">Sign in</Button>
      </form>
    </Card>
  );
}
