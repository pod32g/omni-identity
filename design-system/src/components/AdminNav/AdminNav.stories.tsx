import type { Meta, StoryObj } from "@storybook/react";
import { AdminNav } from "./AdminNav";

const meta: Meta<typeof AdminNav> = {
  title: "Layout/AdminNav",
  component: AdminNav,
  decorators: [(Story) => <div style={{ width: 700 }}>{Story()}</div>],
  args: {
    username: "root",
    links: [
      { label: "Users", href: "/admin/users", active: true },
      { label: "Applications", href: "/admin/clients" },
      { label: "Settings", href: "/admin/settings" },
    ],
  },
};
export default meta;

type Story = StoryObj<typeof AdminNav>;

export const Default: Story = {};
