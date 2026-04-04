/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#1e3a8a',
        success: '#10b981',
        danger: '#ef4444',
        premium: '#8b5cf6',
      },
    },
  },
  plugins: [],
}
