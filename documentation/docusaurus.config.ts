import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)
const PHOBOS_REPOSITORY_URL = 'https://github.com/ls1intum/phobos';
const EDIT_URL = PHOBOS_REPOSITORY_URL + '/tree/main/documentation/';
const PAGE_TITLE = 'Phobos Documentation';

const config: Config = {
    title: PAGE_TITLE,
    tagline: 'Run any program with only the access it was shown to need',
    favicon: 'img/tum-logo-blue.svg',

    // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
    future: {
        v4: true, // Improve compatibility with the upcoming Docusaurus v4
    },

    // GitHub project pages: the site is served from https://ls1intum.github.io/phobos/,
    // so the repository name has to be part of baseUrl. It is case sensitive, and this
    // repository's name is lower case.
    url: 'https://ls1intum.github.io',
    baseUrl: '/phobos/',

    organizationName: 'ls1intum',
    projectName: 'phobos',

    // A dangling cross-reference is a documentation bug, and this documentation is the
    // reference somebody follows while writing a policy that decides what a sandbox permits.
    // Fail the build rather than publish a broken link.
    onBrokenLinks: 'throw',
    onBrokenAnchors: 'throw',

    markdown: {
        // Docusaurus 3 parses .md as MDX by default. These pages are ordinary CommonMark full
        // of bare `<` and `{`: shell usage lines such as `--rights=LETTERS PATH`, `${PHOBOS_HOME}`
        // in running prose, and `<host>[:<port>]` in the policy grammar, all of which MDX would
        // reject. 'detect' keeps .md as CommonMark and reserves MDX for .mdx, so a page opts
        // into JSX by its extension.
        format: 'detect',
        hooks: {
            onBrokenMarkdownLinks: 'throw',
        },
    },

    i18n: {
        defaultLocale: 'en',
        locales: ['en'],
    },

    presets: [
        [
            'classic',
            {
                // Both doc sets are declared as explicit plugin instances below.
                docs: false,
                blog: false,
                theme: {
                    customCss: './src/css/custom.css',
                },
            } satisfies Preset.Options,
        ],
    ],

    themes: [
        [
            require.resolve('@easyops-cn/docusaurus-search-local'),
            /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
            {
                hashed: true,
                language: ['en'],
                indexDocs: true,
                indexBlog: false,
                docsRouteBasePath: ['user', 'contributor'],
                searchContextByPaths: [
                    {
                        label: 'User Documentation',
                        path: 'user',
                    },
                    {
                        label: 'Contributor Documentation',
                        path: 'contributor',
                    },
                ],
                useAllContextsWithNoSearchContext: true,
            },
        ],
    ],

    plugins: [
        // The first content-docs instance intentionally carries no id and therefore uses the
        // reserved 'default' plugin id. Every further instance needs a unique id of its own.
        [
            '@docusaurus/plugin-content-docs',
            {
                path: 'docs/user',
                routeBasePath: 'user',
                sidebarPath: './sidebar-user.ts',
                editUrl: EDIT_URL,
                exclude: ['**/README.md'],
            },
        ],
        [
            '@docusaurus/plugin-content-docs',
            {
                id: 'contributor',
                path: 'docs/contributor',
                routeBasePath: 'contributor',
                sidebarPath: './sidebar-contributor.ts',
                editUrl: EDIT_URL,
                exclude: ['**/README.md'],
            },
        ],
    ],

    themeConfig: {
        image: 'img/tum-logo-blue.svg',
        colorMode: {
            respectPrefersColorScheme: true,
        },
        navbar: {
            title: 'Phobos',
            logo: {
                alt: 'TUM Logo',
                src: 'img/tum-logo-blue.svg',
                srcDark: 'img/tum-logo-blue.svg',
            },
            items: [
                {
                    type: 'docSidebar',
                    sidebarId: 'sidebar',
                    docsPluginId: 'default',
                    position: 'left',
                    label: 'User',
                },
                {
                    type: 'docSidebar',
                    sidebarId: 'sidebar',
                    docsPluginId: 'contributor',
                    position: 'left',
                    label: 'Contributor',
                },
                {
                    href: PHOBOS_REPOSITORY_URL,
                    label: 'GitHub',
                    position: 'right',
                },
            ],
        },
        footer: {
            style: 'dark',
            links: [
                {
                    title: 'Documentation',
                    items: [
                        {
                            label: 'User Documentation',
                            to: '/user/phobos/what-is-phobos',
                        },
                        {
                            label: 'Contributor Documentation',
                            to: '/contributor/how-can-you-contribute',
                        },
                    ],
                },
                {
                    title: 'Community',
                    items: [
                        {
                            label: 'AET Website',
                            href: 'https://aet.cit.tum.de',
                        },
                        {
                            label: 'GitHub - Phobos',
                            href: PHOBOS_REPOSITORY_URL,
                        },
                        {
                            label: 'GitHub - AET Projects',
                            href: 'https://github.com/ls1intum',
                        },
                    ],
                },
                {
                    title: 'Project',
                    items: [
                        {
                            label: 'Ares 2',
                            href: 'https://github.com/ls1intum/Ares2',
                        },
                        {
                            label: 'Licence (MIT)',
                            href: PHOBOS_REPOSITORY_URL + '/blob/main/LICENSE',
                        },
                        {
                            label: 'Security Policy',
                            href: PHOBOS_REPOSITORY_URL + '/blob/main/SECURITY.md',
                        },
                    ],
                },
                {
                    title: 'Legal',
                    items: [
                        {
                            label: 'Imprint',
                            to: '/imprint',
                        },
                        {
                            label: 'Privacy Statement',
                            to: '/privacy',
                        },
                    ],
                },
            ],
            copyright: `© ${new Date().getFullYear()} Technical University of Munich – Built by the Applied Education Technologies (AET) group`,
        },
        prism: {
            theme: prismThemes.github,
            darkTheme: prismThemes.dracula,
            additionalLanguages: ['bash', 'ini', 'json', 'c'],
            // The policy reference pages all show the same example policy file and highlight
            // the one section each page documents, so that reading the section in order walks
            // the example from top to bottom. 'policy-focus' renders that section in red; the
            // default 'highlight' class stays available for ordinary emphasis elsewhere.
            magicComments: [
                {
                    className: 'theme-code-block-highlighted-line',
                    line: 'highlight-next-line',
                    block: { start: 'highlight-start', end: 'highlight-end' },
                },
                {
                    className: 'code-block-policy-focus',
                    line: 'policy-focus-next-line',
                    block: { start: 'policy-focus-start', end: 'policy-focus-end' },
                },
            ],
        },
    },
} as Config;

export default config;
