import React from "react";
import "./Badge.css";
import { cx } from "../../util/cx";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** `ok` (green, active) or `off` (red, disabled). */
  tone: "ok" | "off";
}

/** A small status pill (e.g. active / disabled). */
export function Badge({ tone, className, children, ...rest }: BadgeProps) {
  return (
    <span className={cx("omni-badge", `omni-badge--${tone}`, className)} {...rest}>
      {children}
    </span>
  );
}
