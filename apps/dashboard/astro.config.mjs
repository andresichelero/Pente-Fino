import { defineConfig } from "astro/config";
import node from "@astrojs/node";
import preact from "@astrojs/preact";
import tailwind from "@astrojs/tailwind";

export default defineConfig({
  output: "server",
  adapter: node({
    mode: "standalone",
  }),
  integrations: [
    preact({ compat: true }),
    tailwind(),
  ],
  server: {
    host: "127.0.0.1",
    port: 4321,
  },
});
