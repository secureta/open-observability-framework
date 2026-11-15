import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    {
      name: "oof-cloudflare-asset-imports",
      enforce: "pre",
      load(id) {
        if (id.endsWith(".yar")) {
          const text = readFileSync(id, "utf8");
          return `export default ${JSON.stringify(text)};`;
        }
        if (id.endsWith(".wasm")) {
          return [
            'import { readFileSync } from "node:fs";',
            `export default new WebAssembly.Module(readFileSync(${JSON.stringify(id)}));`,
          ].join("\n");
        }
        return null;
      },
    },
  ],
});
