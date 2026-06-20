import type { Meta, StoryObj } from "@storybook/react";
import { Select } from "./Select";

const meta: Meta<typeof Select> = {
  title: "Primitives/Select",
  component: Select,
  decorators: [(Story) => <div style={{ width: 320 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Select>;

export const ClientType: Story = {
  render: (args) => (
    <Select {...args}>
      <option value="confidential">confidential (server-side, has secret)</option>
      <option value="public">public (SPA/native, uses PKCE)</option>
    </Select>
  ),
};
