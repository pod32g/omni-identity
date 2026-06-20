import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Alert } from "./Alert";

describe("Alert", () => {
  it("renders an error alert by default with role=alert", () => {
    render(<Alert>Something failed</Alert>);
    const el = screen.getByRole("alert");
    expect(el).toHaveClass("omni-alert--error");
  });

  it("renders a success alert with role=status", () => {
    render(<Alert tone="success">Saved</Alert>);
    expect(screen.getByRole("status")).toHaveClass("omni-alert--success");
  });
});
