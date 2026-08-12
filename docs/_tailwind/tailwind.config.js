const path = require('path');

module.exports = {
  content: [path.join(__dirname, '..', 'index.html')],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"Inter"', 'system-ui', 'sans-serif'],
        display: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Display"', '"Inter"', 'system-ui', 'sans-serif'],
        mono: ['"SF Mono"', '"JetBrains Mono"', 'ui-monospace', 'monospace']
      },
      colors: {
        ink: {
          50: '#f6f7f9',
          100: '#e9ebf0',
          200: '#cfd4de',
          300: '#a6aebe',
          400: '#78829a',
          500: '#566073',
          600: '#414a5c',
          700: '#2f3644',
          800: '#1f2530',
          900: '#161b24',
          950: '#0e1219'
        },
        beam: {
          50: '#eef3ff',
          100: '#dbe6ff',
          200: '#bcd0ff',
          300: '#8fb0ff',
          400: '#6690ff',
          500: '#3b6ff5',
          600: '#2a56d8',
          700: '#2244ad',
          800: '#1f3b8c',
          900: '#1d3372'
        }
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4,0,0.6,1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'shimmer': 'shimmer 3s linear infinite'
      },
      keyframes: {
        float: {
          '0%,100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' }
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' }
        }
      }
    }
  }
};
