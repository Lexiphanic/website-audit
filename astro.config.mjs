// @ts-check
import { defineConfig } from "astro/config";
import cloudflare from "@astrojs/cloudflare";
import tailwindcss from "@tailwindcss/vite";

// Lexiphanic Audit - a public current-state website audit.
// Server-rendered on Cloudflare Workers: the checks need to see headers, DNS,
// certificates and HTML from the server side, and the audit itself runs as a
// durable Cloudflare Workflow.
export default defineConfig({
  site: "https://audit.lexiphanic.co.uk",
  output: "server",
  security: {
    checkOrigin: true,
  },
  session: false,
  adapter: cloudflare({
    imageService: "passthrough",
  }),
  trailingSlash: "never",
  build: {
    // External CSS/JS so the CSP can forbid inline styles and scripts.
    inlineStylesheets: "never",
  },
  vite: {
    build: {
      assetsInlineLimit: 0,
    },
    plugins: [tailwindcss()],
  },
});
