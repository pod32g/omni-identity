import React from "react";
import "./Table.css";
import { cx } from "../../util/cx";

export interface TableProps
  extends React.TableHTMLAttributes<HTMLTableElement> {}

/**
 * A styled table. Compose with standard `thead`/`tbody`/`tr`/`th`/`td`;
 * the dark-theme styling is applied automatically.
 */
export function Table({ className, children, ...rest }: TableProps) {
  return (
    <table className={cx("omni-table", className)} {...rest}>
      {children}
    </table>
  );
}
