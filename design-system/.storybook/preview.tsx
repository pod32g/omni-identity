import type { Preview } from "@storybook/react";
import React from "react";
import "../src/tokens.css";
import { ThemeProvider } from "../src/components/ThemeProvider/ThemeProvider";

const preview: Preview = {
  parameters: {
    backgrounds: {
      default: "omni",
      values: [{ name: "omni", value: "#0f1115" }],
    },
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/i } },
  },
  decorators: [
    // Mirror cfg.provider so the Storybook reference and the design-sync
    // previews wrap components in the same dark theme surface.
    (Story) => (
      <ThemeProvider>
        <Story />
      </ThemeProvider>
    ),
  ],
};

export default preview;
