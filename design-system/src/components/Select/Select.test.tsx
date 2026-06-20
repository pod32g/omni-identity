import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Select } from "./Select";

describe("Select", () => {
  it("renders options with the omni-select class", () => {
    render(
      <Select aria-label="type">
        <option value="a">A</option>
        <option value="b">B</option>
      </Select>,
    );
    expect(screen.getByRole("combobox", { name: "type" })).toHaveClass("omni-select");
    expect(screen.getAllByRole("option")).toHaveLength(2);
  });
});
