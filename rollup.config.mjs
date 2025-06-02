import esbuild from 'rollup-plugin-esbuild'
import dts from 'rollup-plugin-dts'

export default [
    {
        input: 'src/index.ts',
        output: {
            dir: 'dist/default/esm',
            format: 'esm',
            entryFileNames: 'index.mjs',
            sourcemap: false
        },
        plugins: [
            esbuild({
            })
        ],
        external: [
            'crypto', 'node:crypto', 'node:tls',
            'headers-polyfill', 'json-stable-stringify',
        ]
    },

    {
        input: 'src/index.ts',
        output: {
            dir: 'dist/default/cjs',
            format: 'cjs',
            entryFileNames: 'index.js',
            sourcemap: false,
        },
        plugins: [
            esbuild()
        ],
        external: [
            'crypto', 'node:crypto', 'node:tls',
            'headers-polyfill', 'json-stable-stringify',
        ]
    },

    {
        input: 'src/index.ts',
        output: {
            file: 'dist/types/index.d.ts',
            format: 'es',
        },
        plugins: [dts()],
        external: [
            'headers-polyfill', 'json-stable-stringify',
        ]
    }
]
