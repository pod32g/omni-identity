import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Card } from "./Card";

describe("Card", () => {
  it("defaults to the wide variant", () => {
    render(<Card>body</Card>);
    expect(screen.getByText("body")).toHaveClass("omni-card", "omni-card--default");
  });

  it("supports the narrow auth variant", () => {
    render(<Card variant="auth">body</Card>);
    expect(screen.getByText("body")).toHaveClass("omni-card--auth");
  });
});
