import type { Meta, StoryObj } from "@storybook/react";
import { Field } from "./Field";
import { Input } from "../Input/Input";

const meta: Meta<typeof Field> = {
  title: "Primitives/Field",
  component: Field,
  decorators: [(Story) => <div style={{ width: 320 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Field>;

export const WithInput: Story = {
  args: { label: "Email" },
  render: (args) => (
    <Field {...args}>
      <Input type="email" placeholder="you@example.com" />
    </Field>
  ),
};

export const WithHint: Story = {
  args: { label: "Scopes", hint: "Space separated, e.g. openid email profile" },
  render: (args) => (
    <Field {...args}>
      <Input defaultValue="openid email profile" />
    </Field>
  ),
};
