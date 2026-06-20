import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Badge } from "./Badge";

describe("Badge", () => {
  it("applies the tone class", () => {
    render(<Badge tone="ok">active</Badge>);
    expect(screen.getByText("active")).toHaveClass("omni-badge", "omni-badge--ok");
  });
});
