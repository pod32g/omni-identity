import type { Meta, StoryObj } from "@storybook/react";
import { Card } from "./Card";

const meta: Meta<typeof Card> = {
  title: "Layout/Card",
  component: Card,
};
export default meta;

type Story = StoryObj<typeof Card>;

export const Default: Story = {
  render: (args) => (
    <Card {...args}>
      <h1 style={{ margin: 0, fontSize: 20 }}>Applications</h1>
      <p style={{ color: "var(--omni-text-muted)", fontSize: 13 }}>
        Register and manage OIDC clients.
      </p>
    </Card>
  ),
};

export const Auth: Story = {
  args: { variant: "auth" },
  render: (args) => (
    <Card {...args}>
      <h1 style={{ margin: 0, fontSize: 20 }}>Omni Identity</h1>
      <p style={{ color: "var(--omni-text-muted)", fontSize: 13 }}>Sign in to continue.</p>
    </Card>
  ),
};
