import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LoginForm } from "./LoginForm";

describe("LoginForm", () => {
  it("renders the username and password fields and submit button", () => {
    render(<LoginForm />);
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("shows an error alert when provided", () => {
    render(<LoginForm error="Invalid username or password." />);
    expect(screen.getByRole("alert")).toHaveTextContent("Invalid username or password.");
  });
});
