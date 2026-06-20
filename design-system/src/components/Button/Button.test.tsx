import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Button } from "./Button";

describe("Button", () => {
  it("renders its label", () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });

  it("defaults to the primary variant", () => {
    render(<Button>Go</Button>);
    expect(screen.getByRole("button")).toHaveClass("omni-btn", "omni-btn--primary");
  });

  it("applies the secondary variant class", () => {
    render(<Button variant="secondary">Cancel</Button>);
    expect(screen.getByRole("button")).toHaveClass("omni-btn--secondary");
  });
});
