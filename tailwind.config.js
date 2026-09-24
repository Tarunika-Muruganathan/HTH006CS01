/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'soc-green': '0 0 28px rgba(52, 211, 153, 0.08)',
        'soc-amber': '0 0 28px rgba(251, 191, 36, 0.08)',
        'soc-orange': '0 0 28px rgba(249, 115, 22, 0.08)',
        'soc-rose': '0 0 28px rgba(244, 63, 94, 0.08)',
      },
    },
  },
  plugins: [],
}
