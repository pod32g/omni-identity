import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Textarea } from "./Textarea";

describe("Textarea", () => {
  it("renders with the omni-textarea class", () => {
    render(<Textarea aria-label="uris" />);
    expect(screen.getByRole("textbox", { name: "uris" })).toHaveClass("omni-textarea");
  });
});
