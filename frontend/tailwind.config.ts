import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        terminal: '#0d1117',
        'terminal-border': '#30363d',
        accent: '#58a6ff',
        danger: '#f85149',
        success: '#3fb950',
        warning: '#d29922',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
