import cleaner from 'rollup-plugin-cleaner'
import dts from 'rollup-plugin-dts'
import esbuild from 'rollup-plugin-esbuild'

import { main, dependencies } from './package.json'
import { compilerOptions } from './tsconfig.json'

/** environment variables */
const env = process.env.NODE_ENV
const isProd = env === 'production'

/** package variables */
const name = main.replace(/\.js$/, '')

/** esbuild config */
const esbuildConfig = {
  minify: isProd,
  target: 'esnext',
  define: {
    __VERSION__: '"x.y.z"',
  },
  loaders: {
    // Add .json files support
    '.json': 'json',
  },
}

const cleanerPluginDist =
  isProd &&
  cleaner({
    targets: [compilerOptions.outDir],
  })

const external = Object.keys(dependencies || {})

const bundle = config => ({
  ...config,
  input: 'src/index.ts',
  external,
})

const configSrc = bundle({
  plugins: [cleanerPluginDist, esbuild(esbuildConfig)],
  output: [
    {
      file: `${name}.js`,
      format: 'cjs',
      sourcemap: true,
    },
    {
      file: `${name}.mjs`,
      format: 'es',
      sourcemap: true,
    },
  ],
})

const configTypings = bundle({
  plugins: [dts()],
  output: {
    file: `${name}.d.ts`,
    format: 'es',
  },
})

export default [configSrc, configTypings]
