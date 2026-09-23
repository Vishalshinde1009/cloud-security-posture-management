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
        cyber: {
          bg: '#080C14',
          dark: '#0B0F19',
          card: '#0F172A',
          cardHover: '#131D35',
          border: '#1E293B',
          borderLight: '#334155',
          accent: '#06B6D4',
          accentBlue: '#3B82F6',
          purple: '#8B5CF6',
          critical: '#F43F5E',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#10B981',
          info: '#6366F1'
        }
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -5px rgba(6, 182, 212, 0.25)',
        'glow-blue': '0 0 20px -5px rgba(59, 130, 246, 0.25)',
        'glow-purple': '0 0 20px -5px rgba(139, 92, 246, 0.25)',
        'glow-critical': '0 0 20px -5px rgba(244, 63, 94, 0.25)',
        'glow-emerald': '0 0 20px -5px rgba(16, 185, 129, 0.25)',
      },
      animation: {
        'pulse-subtle': 'pulseSubtle 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-fast': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float-slow': 'floatSlow 6s ease-in-out infinite',
        'flow-horizontal': 'flowHorizontal 2s linear infinite',
        'radar-sweep': 'radarSweep 8s linear infinite',
        'spin-slow': 'spin 20s linear infinite',
        'pulse-glow': 'pulseGlow 3s ease-in-out infinite',
      },
      keyframes: {
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
        floatSlow: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-6px)' },
        },
        flowHorizontal: {
          '0%': { strokeDashoffset: '24' },
          '100%': { strokeDashoffset: '0' },
        },
        radarSweep: {
          'from': { transform: 'rotate(0deg)' },
          'to': { transform: 'rotate(360deg)' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.3', transform: 'scale(1)' },
          '50%': { opacity: '0.7', transform: 'scale(1.04)' },
        },
      }
    },
  },
  plugins: [],
}
