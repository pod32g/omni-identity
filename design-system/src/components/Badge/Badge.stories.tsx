import type { Meta, StoryObj } from "@storybook/react";
import { Badge } from "./Badge";

const meta: Meta<typeof Badge> = {
  title: "Data/Badge",
  component: Badge,
};
export default meta;

type Story = StoryObj<typeof Badge>;

export const Active: Story = { args: { tone: "ok", children: "active" } };
export const Disabled: Story = { args: { tone: "off", children: "disabled" } };
