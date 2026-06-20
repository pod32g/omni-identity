import type { Meta, StoryObj } from "@storybook/react";
import { SetupForm } from "./SetupForm";

const meta: Meta<typeof SetupForm> = {
  title: "Screens/SetupForm",
  component: SetupForm,
};
export default meta;

type Story = StoryObj<typeof SetupForm>;

export const Default: Story = {};
export const WithError: Story = {
  args: { error: "Username or email may be taken." },
};
