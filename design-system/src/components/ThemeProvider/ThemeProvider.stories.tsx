import type { Meta, StoryObj } from "@storybook/react";
import { ThemeProvider } from "./ThemeProvider";
import { Button } from "../Button/Button";
import { Badge } from "../Badge/Badge";

const meta: Meta<typeof ThemeProvider> = {
  title: "Layout/ThemeProvider",
  component: ThemeProvider,
};
export default meta;

type Story = StoryObj<typeof ThemeProvider>;

export const Default: Story = {
  render: (args) => (
    <ThemeProvider {...args}>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Button>Save changes</Button>
        <Badge tone="ok">active</Badge>
      </div>
    </ThemeProvider>
  ),
};
