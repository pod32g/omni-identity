import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AdminNav } from "./AdminNav";

const links = [
  { label: "Users", href: "/admin/users", active: true },
  { label: "Applications", href: "/admin/clients" },
];

describe("AdminNav", () => {
  it("renders brand, links, and username", () => {
    render(<AdminNav links={links} username="root" />);
    expect(screen.getByText("Omni Identity")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Users" })).toHaveAttribute("href", "/admin/users");
    expect(screen.getByText("root")).toBeInTheDocument();
  });

  it("calls onSignOut when sign out is clicked", async () => {
    const onSignOut = vi.fn();
    render(<AdminNav links={links} onSignOut={onSignOut} />);
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(onSignOut).toHaveBeenCalledOnce();
  });
});
