/**
 * The twelve Policy Reference pages show one example policy file between them, and each marks
 * its own section of it in red.
 *
 * Nothing else holds them together. The pages are separate files, so an editor who changes the
 * example on the page they are reading leaves eleven copies saying something different, and
 * the Docusaurus build cannot see it: a code block is text to it. This is that check.
 *
 * Run with `pnpm run test:structure`.
 */

import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import test, { describe } from 'node:test';

/** Where the Policy Reference lives, relative to this file. */
const REFERENCE = path.resolve(import.meta.dirname, '..', 'docs', 'user', 'policy-reference');

/** The fence the shared example is written in, and the markers that colour one section. */
const EXAMPLE = /```ini title="exercise\.cfg"\n([\s\S]*?)```/;
const FOCUS_START = '# policy-focus-start';
const FOCUS_END = '# policy-focus-end';

/** Every section page, which is every Markdown file there except the index. */
async function sectionPages() {
    const names = (await readdir(REFERENCE))
        .filter((name) => name.endsWith('.md') && name !== 'index.md')
        .sort();
    const pages = [];
    for (const name of names) {
        pages.push({ name, text: await readFile(path.join(REFERENCE, name), 'utf8') });
    }
    return pages;
}

/** The example block of one page, and the marked region inside it. */
function exampleOf(page) {
    const match = EXAMPLE.exec(page.text);
    assert.ok(match !== null, `${page.name} shows no example policy file`);
    const lines = match[1].split('\n');
    const start = lines.indexOf(FOCUS_START);
    const end = lines.indexOf(FOCUS_END);
    assert.ok(start !== -1, `${page.name} does not open a marked region`);
    assert.ok(end > start, `${page.name} does not close its marked region after opening it`);
    return {
        marked: lines.slice(start + 1, end),
        without: lines.filter((line) => line !== FOCUS_START && line !== FOCUS_END).join('\n'),
    };
}

describe('the shared example policy file', () => {
    test('there is one page per section the reference documents', async () => {
        const pages = await sectionPages();
        assert.equal(pages.length, 12, 'twelve sections, twelve pages');
    });

    test('every page shows the same file once the markers are removed', async () => {
        const pages = await sectionPages();
        const [first, ...rest] = pages.map((page) => ({ name: page.name, ...exampleOf(page) }));
        for (const page of rest) {
            assert.equal(page.without, first.without,
                `${page.name} shows a different example from ${first.name}`);
        }
    });

    test('every page marks its own section, and only that section', async () => {
        for (const page of await sectionPages()) {
            const section = `[${page.name.replace(/\.md$/, '')}]`;
            const { marked } = exampleOf(page);
            assert.equal(marked[0], section,
                `${page.name} marks ${marked[0]} rather than ${section}`);
            const headers = marked.filter((line) => /^\[[a-z-]+\]$/.test(line));
            assert.deepEqual(headers, [section],
                `${page.name} marks more than its own section`);
        }
    });
});
