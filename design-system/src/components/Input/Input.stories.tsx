import type { Meta, StoryObj } from "@storybook/react";
import { Input } from "./Input";

const meta: Meta<typeof Input> = {
  title: "Primitives/Input",
  component: Input,
  args: { placeholder: "you@example.com" },
  decorators: [(Story) => <div style={{ width: 320 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Input>;

export const Default: Story = {};
export const Password: Story = { args: { type: "password", placeholder: "••••••••" } };
export const Disabled: Story = { args: { disabled: true, value: "locked" } };
