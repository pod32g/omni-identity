import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Table } from "./Table";

describe("Table", () => {
  it("renders a styled table with headers and cells", () => {
    render(
      <Table>
        <thead>
          <tr>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Jellyfin</td>
          </tr>
        </tbody>
      </Table>,
    );
    expect(screen.getByRole("table")).toHaveClass("omni-table");
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Jellyfin" })).toBeInTheDocument();
  });
});
