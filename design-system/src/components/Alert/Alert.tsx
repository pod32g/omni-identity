import React from "react";
import "./Alert.css";
import { cx } from "../../util/cx";

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  /** `error` (red) or `success` (green). */
  tone?: "error" | "success";
}

/** An inline banner for form errors and confirmations. */
export function Alert({ tone = "error", className, children, ...rest }: AlertProps) {
  return (
    <div
      className={cx("omni-alert", `omni-alert--${tone}`, className)}
      role={tone === "error" ? "alert" : "status"}
      {...rest}
    >
      {children}
    </div>
  );
}
