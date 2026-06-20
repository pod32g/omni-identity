import type { Meta, StoryObj } from "@storybook/react";
import { Textarea } from "./Textarea";

const meta: Meta<typeof Textarea> = {
  title: "Primitives/Textarea",
  component: Textarea,
  decorators: [(Story) => <div style={{ width: 360 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Textarea>;

export const RedirectURIs: Story = {
  args: {
    placeholder: "https://app.example.com/callback",
    defaultValue: "https://jelly.example.com/callback\nhttps://jelly.example.com/sso",
  },
};
