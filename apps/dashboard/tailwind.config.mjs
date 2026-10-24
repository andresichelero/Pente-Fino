/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  theme: {
    extend: {
      colors: {
        "bg-abyss": "#090d16",
        "bg-panel": "#111827",
        "border-grid": "#1f2937",
        "accent-emerald": "#10b981",
        "accent-cyan": "#06b6d4",
        "accent-amber": "#f59e0b",
        "accent-crimson": "#ef4444",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
