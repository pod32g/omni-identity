import type { Meta, StoryObj } from "@storybook/react";
import { Table } from "./Table";
import { Badge } from "../Badge/Badge";
import { Code } from "../Code/Code";

const meta: Meta<typeof Table> = {
  title: "Data/Table",
  component: Table,
  decorators: [(Story) => <div style={{ width: 560 }}>{Story()}</div>],
};
export default meta;

type Story = StoryObj<typeof Table>;

export const Clients: Story = {
  render: (args) => (
    <Table {...args}>
      <thead>
        <tr>
          <th>Name</th>
          <th>Client ID</th>
          <th>Type</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Jellyfin</td>
          <td>
            <Code>jellyfin</Code>
          </td>
          <td>confidential</td>
          <td>
            <Badge tone="ok">active</Badge>
          </td>
        </tr>
        <tr>
          <td>Omni Metrics</td>
          <td>
            <Code>omni-metrics</Code>
          </td>
          <td>confidential</td>
          <td>
            <Badge tone="off">disabled</Badge>
          </td>
        </tr>
      </tbody>
    </Table>
  ),
};
