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
        ember: {
          50: '#fff4ed',
          100: '#ffe6d4',
          200: '#ffc8a8',
          300: '#ffa371',
          400: '#ff7838',
          500: '#fa5510',
          600: '#eb3d06',
          700: '#c32d07',
          800: '#9b260f',
          900: '#7d2310'
        },
        coal: {
          50: '#f7f5f3',
          100: '#e9e5e1',
          200: '#d0c9c2',
          300: '#a89e94',
          400: '#7d736a',
          500: '#5d544c',
          600: '#48413b',
          700: '#3a3530',
          800: '#2c2825',
          900: '#1a1612',
          950: '#0f0a07'
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
