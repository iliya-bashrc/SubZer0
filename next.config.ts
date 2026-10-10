import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Static export keeps the existing GitHub Pages hosting model intact.
  output: 'export',
  // Site is served from /SubZer0/ on github.io — asset URLs must carry basePath.
  basePath: '/SubZer0',
  images: { unoptimized: true },
  trailingSlash: true,
};

export default nextConfig;
