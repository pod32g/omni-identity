import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Field } from "./Field";

describe("Field", () => {
  it("associates the label with the control and shows the hint", () => {
    render(
      <Field label="Email" hint="we never share it">
        <input />
      </Field>,
    );
    expect(screen.getByText("Email")).toBeInTheDocument();
    // Label wraps the control, so the textbox is accessible by the label text.
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByText("we never share it")).toHaveClass("omni-field__hint");
  });
});
