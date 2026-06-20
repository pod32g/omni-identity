import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  // React is provided by the host (design-sync vendors it); keep it external.
  external: ["react", "react-dom", "react/jsx-runtime"],
  // Component CSS (and tokens) bundle into a single dist/index.css.
  injectStyle: false,
});
