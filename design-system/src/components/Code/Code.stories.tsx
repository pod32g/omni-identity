import type { Meta, StoryObj } from "@storybook/react";
import { Code } from "./Code";

const meta: Meta<typeof Code> = {
  title: "Data/Code",
  component: Code,
  args: { children: "jellyfin" },
};
export default meta;

type Story = StoryObj<typeof Code>;

export const ClientId: Story = {};
export const Url: Story = { args: { children: "https://id.omni.local/jwks.json" } };
