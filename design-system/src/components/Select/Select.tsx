import React from "react";
import "./Select.css";
import { cx } from "../../util/cx";

export interface SelectProps
  extends React.SelectHTMLAttributes<HTMLSelectElement> {}

/** A native select styled for the dark theme, with a custom caret. */
export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  function Select({ className, children, ...rest }, ref) {
    return (
      <select ref={ref} className={cx("omni-select", className)} {...rest}>
        {children}
      </select>
    );
  },
);
