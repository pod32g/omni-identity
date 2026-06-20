import type { Preview } from "@storybook/react";
import React from "react";
import "../src/tokens.css";

const preview: Preview = {
  parameters: {
    layout: "centered",
    backgrounds: {
      default: "omni",
      values: [{ name: "omni", value: "#0f1115" }],
    },
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/i } },
  },
  decorators: [
    (Story) => (
      <div
        style={{
          color: "var(--omni-text)",
          font: "var(--omni-font-body)",
          padding: 24,
        }}
      >
        <Story />
      </div>
    ),
  ],
};

export default preview;
