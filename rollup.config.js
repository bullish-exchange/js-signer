import cleaner from 'rollup-plugin-cleaner'
import dts from 'rollup-plugin-dts'
import esbuild from 'rollup-plugin-esbuild'
import { visualizer } from 'rollup-plugin-visualizer'

import { main, dependencies } from './package.json'
import { compilerOptions } from './tsconfig.json'

/** environment variables */
const env = process.env.NODE_ENV
const isProd = env === 'production'

/** package variables */
const name = main.replace(/\.js$/, '')

/** esbuild, cleaner, visualizer config */
const config = {
  esbuild: {
    minify: isProd,
    target: 'es6',
    define: {
      __VERSION__: '"x.y.z"',
    },
    loaders: {
      '.json': 'json',
    },
  },
  visualizer: {
    emitFile: true,
    file: 'stats.html',
    template: 'treemap',
  },
  cleaner: {
    targets: [compilerOptions.outDir],
  },
}

const cleanerPluginDist = isProd && cleaner(config.cleaner)

const visualizePluginDist = !isProd && visualizer(config.visualizer)

const external = Object.keys(dependencies || {})

const bundle = config => ({
  ...config,
  input: 'src/index.ts',
  external,
})

const configSrc = bundle({
  plugins: [cleanerPluginDist, esbuild(config.esbuild), visualizePluginDist],
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
