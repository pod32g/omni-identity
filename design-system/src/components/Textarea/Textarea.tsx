import React from "react";
import "./Textarea.css";
import { cx } from "../../util/cx";

export interface TextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {}

/** A multi-line text area (e.g. redirect URIs, one per line). */
export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  function Textarea({ className, rows = 3, ...rest }, ref) {
    return (
      <textarea ref={ref} rows={rows} className={cx("omni-textarea", className)} {...rest} />
    );
  },
);
