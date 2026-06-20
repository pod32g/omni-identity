import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Callout } from "./Callout";

describe("Callout", () => {
  it("renders the title and body", () => {
    render(<Callout title="Secret">value-123</Callout>);
    expect(screen.getByText("Secret")).toHaveClass("omni-callout__title");
    expect(screen.getByText("value-123")).toBeInTheDocument();
  });
});
