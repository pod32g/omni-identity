import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SetupForm } from "./SetupForm";

describe("SetupForm", () => {
  it("renders username, email, and password fields", () => {
    render(<SetupForm />);
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create admin/ })).toBeInTheDocument();
  });
});
