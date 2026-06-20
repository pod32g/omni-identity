import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PageShell } from "./PageShell";

describe("PageShell", () => {
  it("centers content by default", () => {
    render(<PageShell>content</PageShell>);
    expect(screen.getByText("content")).toHaveClass("omni-page", "omni-page--center");
  });

  it("can disable centering", () => {
    render(<PageShell center={false}>content</PageShell>);
    expect(screen.getByText("content")).not.toHaveClass("omni-page--center");
  });
});
