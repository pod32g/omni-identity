import React from "react";
import "./Field.css";
import { cx } from "../../util/cx";

export interface FieldProps {
  /** The field label text. */
  label: string;
  /** The control (Input, Select, Textarea, …). */
  children: React.ReactNode;
  /** Optional helper text shown under the control. */
  hint?: React.ReactNode;
  className?: string;
}

/** A labelled form field: a label stacked above its control, with an optional hint. */
export function Field({ label, children, hint, className }: FieldProps) {
  return (
    <div className={cx("omni-field", className)}>
      {/* The label wraps only its text + control, so the hint never pollutes
          the control's accessible name. */}
      <label className="omni-field__control">
        <span className="omni-field__label">{label}</span>
        {children}
      </label>
      {hint ? <span className="omni-field__hint">{hint}</span> : null}
    </div>
  );
}
