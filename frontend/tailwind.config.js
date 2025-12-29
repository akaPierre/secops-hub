/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cybersecurity dark theme
        'cyber-dark': '#0a0e27',
        'cyber-darker': '#060916',
        'cyber-blue': '#00d4ff',
        'cyber-purple': '#b537f2',
        'cyber-green': '#00ff88',
        'cyber-red': '#ff3366',
        'cyber-yellow': '#ffd700',
        'cyber-gray': '#1a1f3a',
      },
      fontFamily: {
        'mono': ['Courier New', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          'from': { boxShadow: '0 0 5px #00d4ff, 0 0 10px #00d4ff' },
          'to': { boxShadow: '0 0 10px #00d4ff, 0 0 20px #00d4ff, 0 0 30px #00d4ff' }
        }
      }
    },
  },
  plugins: [],
}