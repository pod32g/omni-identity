import React from "react";
import "./Callout.css";
import { cx } from "../../util/cx";

export interface CalloutProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  /** Bold heading shown above the body (e.g. "Client secret (shown once)"). */
  title?: React.ReactNode;
}

/** A success-toned notice block — used to reveal a one-time secret. */
export function Callout({ title, className, children, ...rest }: CalloutProps) {
  return (
    <div className={cx("omni-callout", className)} {...rest}>
      {title ? <strong className="omni-callout__title">{title}</strong> : null}
      <div className="omni-callout__body">{children}</div>
    </div>
  );
}
