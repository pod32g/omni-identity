import type { Meta, StoryObj } from "@storybook/react";
import { LoginForm } from "./LoginForm";

const meta: Meta<typeof LoginForm> = {
  title: "Screens/LoginForm",
  component: LoginForm,
};
export default meta;

type Story = StoryObj<typeof LoginForm>;

export const Default: Story = {};
export const WithError: Story = {
  args: { error: "Invalid username or password." },
};
