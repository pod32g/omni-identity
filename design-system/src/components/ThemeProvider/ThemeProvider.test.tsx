import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ThemeProvider } from "./ThemeProvider";

describe("ThemeProvider", () => {
  it("wraps children in the dark theme surface", () => {
    render(
      <ThemeProvider>
        <span>content</span>
      </ThemeProvider>,
    );
    const child = screen.getByText("content");
    expect(child.parentElement).toHaveClass("omni-theme");
  });
});
