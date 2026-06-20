import React from "react";
import "./Button.css";
import { cx } from "../../util/cx";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Visual style. `primary` is the accent action; `secondary` is muted. */
  variant?: "primary" | "secondary";
}

/** The Omni Identity button. Primary is the accent call-to-action. */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  function Button({ variant = "primary", className, type = "button", ...rest }, ref) {
    return (
      <button
        ref={ref}
        type={type}
        className={cx("omni-btn", `omni-btn--${variant}`, className)}
        {...rest}
      />
    );
  },
);
