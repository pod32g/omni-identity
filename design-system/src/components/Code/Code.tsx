import React from "react";
import "./Code.css";
import { cx } from "../../util/cx";

export interface CodeProps extends React.HTMLAttributes<HTMLElement> {}

/** Inline monospace code chip (client IDs, URLs, tokens). */
export function Code({ className, children, ...rest }: CodeProps) {
  return (
    <code className={cx("omni-code", className)} {...rest}>
      {children}
    </code>
  );
}
