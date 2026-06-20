import type { Meta, StoryObj } from "@storybook/react";
import { Button } from "./Button";

const meta: Meta<typeof Button> = {
  title: "Primitives/Button",
  component: Button,
  args: { children: "Save changes" },
};
export default meta;

type Story = StoryObj<typeof Button>;

export const Primary: Story = {};
export const Secondary: Story = {
  args: { variant: "secondary", children: "Cancel" },
};
export const Disabled: Story = { args: { disabled: true } };
