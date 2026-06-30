import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        win95: {
          gray: "#C0C0C0",
          darkGray: "#808080",
          navy: "#000080",
          blue: "#0000FF",
          lightBlue: "#1084D0",
          green: "#00FF00",
          red: "#FF0000",
          yellow: "#FFFF00",
        }
      },
      fontFamily: {
        sans: ["'MS Sans Serif'", "Tahoma", "sans-serif"],
        heading: ["'Arial Black'", "Impact", "sans-serif"],
        mono: ["'Courier New'", "monospace"],
      }
    },
  },
  plugins: [],
};
export default config;
