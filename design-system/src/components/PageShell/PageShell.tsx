import React from "react";
import "./PageShell.css";
import { cx } from "../../util/cx";

export interface PageShellProps
  extends React.HTMLAttributes<HTMLDivElement> {
  /** When true, vertically+horizontally center the content (login/setup pages). */
  center?: boolean;
}

/** Full-height dark page background that frames a Card. */
export function PageShell({ center = true, className, children, ...rest }: PageShellProps) {
  return (
    <div
      className={cx("omni-page", center && "omni-page--center", className)}
      {...rest}
    >
      {children}
    </div>
  );
}
