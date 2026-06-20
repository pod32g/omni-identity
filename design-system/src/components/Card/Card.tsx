import React from "react";
import "./Card.css";
import { cx } from "../../util/cx";

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** `default` is the wide admin card; `auth` is the narrow login/setup card. */
  variant?: "default" | "auth";
}

/** The surface container that frames a page's content. */
export function Card({ variant = "default", className, children, ...rest }: CardProps) {
  return (
    <div className={cx("omni-card", `omni-card--${variant}`, className)} {...rest}>
      {children}
    </div>
  );
}
