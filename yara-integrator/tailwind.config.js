/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        primary: "#3A606E",
        secondary: "#607B7D",
        staleGray: "#607B7D",
        battleshipGray: "#828E82",
        sage: "#AAAE8E",
        bg: "#E0E0E0",
        correctGreen: "#23A347",
      },
    },
  },
  plugins: [],
};
