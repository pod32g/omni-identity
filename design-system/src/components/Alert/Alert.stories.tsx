import type { Meta, StoryObj } from "@storybook/react";
import { Alert } from "./Alert";

const meta: Meta<typeof Alert> = {
  title: "Feedback/Alert",
  component: Alert,
  decorators: [(Story) => <div style={{ width: 360 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Alert>;

export const Error: Story = {
  args: { tone: "error", children: "Invalid username or password." },
};
export const Success: Story = {
  args: { tone: "success", children: "Client updated." },
};
