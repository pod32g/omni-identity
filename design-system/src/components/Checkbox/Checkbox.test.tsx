import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Checkbox } from "./Checkbox";

describe("Checkbox", () => {
  it("renders a checkbox labelled by its text", () => {
    render(<Checkbox label="Administrator" />);
    expect(screen.getByRole("checkbox", { name: "Administrator" })).toBeInTheDocument();
  });
});
