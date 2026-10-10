/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        pentest: {
          900: '#0a0e1a',
          800: '#111827',
          700: '#1a2332',
          600: '#243044',
          500: '#2d3b52',
        },
        neon: {
          green: '#00ff88',
          blue: '#00aaff',
          red: '#ff3366',
          yellow: '#ffaa00',
          purple: '#aa44ff',
        },
      },
    },
  },
  plugins: [],
}
