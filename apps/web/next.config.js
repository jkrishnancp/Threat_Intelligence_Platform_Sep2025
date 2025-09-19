/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    outputFileTracingIncludes: {
      '/': ['./packages/**/*'],
    },
  },
  transpilePackages: ['@tip/db'],
}

module.exports = nextConfig