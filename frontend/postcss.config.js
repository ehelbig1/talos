import autoprefixer from 'autoprefixer';

// @tailwindcss/vite plugin (in vite.config.ts) handles all Tailwind processing.
// PostCSS only needs autoprefixer here; having @tailwindcss/postcss alongside
// @tailwindcss/vite causes a dual-plugin conflict that prevents spacing/color
// utilities from being generated.
export default {
  plugins: [autoprefixer],
};
