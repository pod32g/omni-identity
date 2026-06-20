import type { Meta, StoryObj } from "@storybook/react";
import { Callout } from "./Callout";
import { Code } from "../Code/Code";

const meta: Meta<typeof Callout> = {
  title: "Feedback/Callout",
  component: Callout,
  decorators: [(Story) => <div style={{ width: 420 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Callout>;

export const SecretReveal: Story = {
  args: { title: "Client secret (shown once — copy it now):" },
  render: (args) => (
    <Callout {...args}>
      <Code>s3cr3t_9f2a1c4e8b7d0a6f3e2c1b9a8d7c6e5f</Code>
    </Callout>
  ),
};
