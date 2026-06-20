import React from "react";
import "./ThemeProvider.css";
import "../../tokens.css";
import { cx } from "../../util/cx";

export interface ThemeProviderProps
  extends React.HTMLAttributes<HTMLDivElement> {}

/**
 * Establishes the Omni Identity dark theme surface. Wrap an app (or any region)
 * in this so the design tokens, dark background, and base text color apply.
 * Every other component is designed to render on this surface.
 */
export function ThemeProvider({ className, children, ...rest }: ThemeProviderProps) {
  return (
    <div className={cx("omni-theme", className)} {...rest}>
      {children}
    </div>
  );
}
