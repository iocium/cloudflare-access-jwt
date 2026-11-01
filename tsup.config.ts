import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    verify: 'src/verify.ts',
    'middleware/hono': 'src/middleware/hono.ts',
    'middleware/itty': 'src/middleware/itty.ts',
    'middleware/express': 'src/middleware/express.ts',
    'middleware/fastify': 'src/middleware/fastify.ts',
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  // Frameworks are optional peer dependencies — never bundle them.
  external: ['hono', 'express', 'fastify', 'itty-router'],
})
