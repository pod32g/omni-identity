import React from "react";
import "./Checkbox.css";
import { cx } from "../../util/cx";

export interface CheckboxProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  /** The label shown beside the checkbox. */
  label: string;
}

/** A checkbox with an inline label (e.g. "Administrator"). */
export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  function Checkbox({ label, className, ...rest }, ref) {
    return (
      <label className={cx("omni-checkbox", className)}>
        <input ref={ref} type="checkbox" {...rest} />
        <span>{label}</span>
      </label>
    );
  },
);
