import React from "react";
import "./Input.css";
import { cx } from "../../util/cx";

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {}

/** A single-line text/password/email input styled for the dark theme. */
export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  function Input({ className, type = "text", ...rest }, ref) {
    return (
      <input ref={ref} type={type} className={cx("omni-input", className)} {...rest} />
    );
  },
);
