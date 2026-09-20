/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        poseidon: {
          base: '#080c14',
          surface: '#0f172a',
          elevated: '#1e293b',
          border: '#334155',
          borderLight: '#475569',
          cyan: '#38bdf8',
          cyanDark: '#0284c7',
          gold: '#f59e0b',
          goldDark: '#d97706',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          benign: '#10b981',
          neutral: '#94a3b8'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      }
    },
  },
  plugins: [],
}
