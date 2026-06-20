import type { Meta, StoryObj } from "@storybook/react";
import { PageShell } from "./PageShell";
import { Card } from "../Card/Card";

const meta: Meta<typeof PageShell> = {
  title: "Layout/PageShell",
  component: PageShell,
  parameters: { layout: "fullscreen" },
};
export default meta;

type Story = StoryObj<typeof PageShell>;

export const Centered: Story = {
  render: (args) => (
    <PageShell {...args}>
      <Card variant="auth">
        <h1 style={{ margin: 0, fontSize: 20 }}>Omni Identity</h1>
        <p style={{ color: "var(--omni-text-muted)", fontSize: 13 }}>Sign in to continue.</p>
      </Card>
    </PageShell>
  ),
};
