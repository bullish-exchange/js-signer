import cleaner from 'rollup-plugin-cleaner'
import dts from 'rollup-plugin-dts'
import esbuild from 'rollup-plugin-esbuild'
import { visualizer } from 'rollup-plugin-visualizer'

import tsconfig from './tsconfig.json' with { type: 'json' }

const isProd = process.env.NODE_ENV === 'production'

export default {
  plugins: [
    isProd && cleaner({ targets: [tsconfig.compilerOptions.outDir] }),
    esbuild({
      target: 'es2023',
      define: {
        __VERSION__: '"x.y.z"',
      },
      loaders: {
        '.json': 'json',
      },
    }),
    dts(),
    !isProd &&
      visualizer({
        emitFile: true,
        file: 'stats.html',
        template: 'treemap',
      }),
  ],
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/index.cjs.js',
      format: 'cjs',
      sourcemap: true,
    },
    {
      file: 'dist/index.js',
      format: 'es',
      sourcemap: true,
    },
    { file: 'dist/index.d.ts', format: 'es' },
  ],
}