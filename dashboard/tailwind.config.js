/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ['Rajdhani', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
      },
      colors: {
        cerberus: {
          primary: '#00ff41',
          danger: '#ff0040',
          warning: '#ffaa00',
          dark: '#0a0e14',
          darker: '#050810',
        }
      },
      backgroundImage: {
        'cerberus-grid': 'linear-gradient(rgba(0, 255, 65, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 65, 0.04) 1px, transparent 1px)',
        'cerberus-radial': 'radial-gradient(circle at top left, rgba(0, 255, 65, 0.25), transparent 45%), radial-gradient(circle at bottom right, rgba(255, 0, 64, 0.2), transparent 40%)',
      },
      boxShadow: {
        neon: '0 0 25px rgba(0, 255, 65, 0.35)',
        card: '0 15px 60px rgba(5, 8, 16, 0.75)',
      },
      animation: {
        'pulse-red': 'pulse-red 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slide-in 0.3s ease-out',
        'reroute': 'reroute 2s ease-in-out',
        'scan': 'scan 3s linear infinite',
        'glow': 'glow 4s ease-in-out infinite',
      },
      keyframes: {
        'pulse-red': {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.5 },
        },
        'slide-in': {
          '0%': { transform: 'translateX(100%)', opacity: 0 },
          '100%': { transform: 'translateX(0)', opacity: 1 },
        },
        'reroute': {
          '0%': { transform: 'translateX(0)' },
          '50%': { transform: 'translateX(50%) translateY(-20px)' },
          '100%': { transform: 'translateX(100%)' },
        },
        'scan': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'glow': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(0, 255, 65, 0.25)' },
          '50%': { boxShadow: '0 0 35px rgba(0, 255, 65, 0.5)' },
        }
      }
    },
  },
  plugins: [],
}
