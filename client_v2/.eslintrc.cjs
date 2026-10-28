const path = require('path');

module.exports = {
    plugins: ['prettier', 'solid', 'import'],
    extends: [
        'prettier',
        'eslint:recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:solid/typescript',
    ],
    parser: '@typescript-eslint/parser',
    env: {
        node: true,
        browser: true,
        commonjs: true,
    },
    settings: {
        'import/core-modules': ['Twosky'],
        'import/resolver': {
            typescript: {
                alwaysTryTypes: true,
                project: [path.resolve(__dirname, 'tsconfig.json')],
            },
            node: {
                extensions: ['.js', '.jsx', '.ts', '.tsx'],
            },
        },
    },
    rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-unused-vars': [
            'error',
            {
                varsIgnorePattern: '^_',
                argsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_',
            },
        ],
        'import/extensions': 'off',
        'class-methods-use-this': 'off',
        'no-shadow': 'off',
        camelcase: 'off',
        'no-console': [
            'warn',
            {
                allow: ['warn', 'error'],
            },
        ],
        'import/no-extraneous-dependencies': [
            'error',
            {
                devDependencies: true,
            },
        ],
        'import/prefer-default-export': 'off',
        'no-alert': 'off',
        'arrow-body-style': 'off',
        'max-len': [
            'error',
            120,
            2,
            {
                ignoreUrls: true,
                ignoreComments: false,
                ignoreRegExpLiterals: true,
                ignoreStrings: true,
                ignoreTemplateLiterals: true,
            },
        ],
        'no-restricted-properties': [
            'error',
            {
                property: 'toSorted',
                message:
                    'ES2023; the WebViews the panel runs in do not support it. Copy the array and sort it.',
            },
            {
                property: 'toReversed',
                message:
                    'ES2023; the WebViews the panel runs in do not support it. Copy the array and reverse it.',
            },
            {
                property: 'toSpliced',
                message:
                    'ES2023; the WebViews the panel runs in do not support it. Copy the array and splice it.',
            },
            {
                object: 'Object',
                property: 'hasOwn',
                message: 'ES2022; use Object.prototype.hasOwnProperty.call.',
            },
        ],
        // A bare global is an Identifier, not a MemberExpression, so
        // no-restricted-properties cannot see it.
        'no-restricted-globals': [
            'error',
            {
                name: 'structuredClone',
                message: 'Chrome 98+; not available in the WebViews we target.',
            },
        ],
    },
    overrides: [
        {
            // Orval-generated files — max-len is controlled by prettier
            files: ['src/api/generated.ts', 'src/api/model/**/*.ts'],
            rules: {
                'max-len': 'off',
            },
        },
    ],
};
