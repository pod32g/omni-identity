import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Code } from "./Code";

describe("Code", () => {
  it("renders inline code with the omni-code class", () => {
    render(<Code>jellyfin</Code>);
    expect(screen.getByText("jellyfin")).toHaveClass("omni-code");
  });
});
