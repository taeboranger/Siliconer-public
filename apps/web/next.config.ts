import type { NextConfig } from 'next';
import path from 'node:path';

const config: NextConfig = {
  output: 'standalone',
  outputFileTracingRoot: path.resolve(import.meta.dirname, '../..'),
  poweredByHeader: false,
  async rewrites() {
    return [{ source: '/api/:path*', destination: `${process.env.SILICONER_API_INTERNAL_URL || 'http://127.0.0.1:4100'}/api/:path*` }];
  },
};
export default config;
