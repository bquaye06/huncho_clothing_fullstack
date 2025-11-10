/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/templates/**/*.html',
    './app/**/*.py',
    './app/static/js/**/*.js'
  ],
  theme: {
    extend: {
      colors: {
        primary: '#E11D48',
        dark: '#0F172A'
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif']
      }
    }
  },
  plugins: []
};
