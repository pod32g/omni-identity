import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Input } from "./Input";

describe("Input", () => {
  it("renders with the omni-input class", () => {
    render(<Input placeholder="Username" />);
    expect(screen.getByPlaceholderText("Username")).toHaveClass("omni-input");
  });

  it("forwards the type attribute", () => {
    render(<Input type="password" placeholder="pw" />);
    expect(screen.getByPlaceholderText("pw")).toHaveAttribute("type", "password");
  });
});
