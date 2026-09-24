/**
 * Finds where the documentation breaks the writing rules, by reading the Markdown syntax
 * tree rather than the lines.
 *
 * A line scanner cannot do this job. It has to be taught inline code, indented code,
 * reference links, link labels as against link targets, tables, block quotations, HTML,
 * directives, YAML quoting and escaped punctuation, and it still reports a string rather
 * than a file, a line and a column. The tree already knows all of that, so the only question
 * left here is which nodes hold text a reader reads.
 *
 * Eligible prose is: paragraphs, headings and table cells, wherever they sit; the `title`
 * and `description` of the front matter, which are what search results show; the `alt` text
 * of an image; and the `label` of a `_category_.json`, which is what the sidebar shows.
 * Code, whether fenced or between backticks, is never eligible, and neither is the target of
 * a link, so `initialize()` in a signature and `?initialize=true` in a URL are both left
 * alone.
 *
 * Inline code is flattened to a single NUL rather than removed. Removing it would join the
 * words on either side into one that nobody wrote.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkFrontmatter from 'remark-frontmatter';
import remarkGfm from 'remark-gfm';
import remarkDirective from 'remark-directive';
import remarkMdx from 'remark-mdx';

import {
    ABBREVIATIONS, ABBREVIATION_RULE, OPENER_RULE, PASSIVE_RULE, RULE_IDS,
    SENTENCE_LENGTH_RULE, WORD_RULES,
} from './rules.mjs';

/** The placeholder a stretch of code becomes, so no rule can match across it. */
const CODE = '\0';

/** A suppression: the rule it silences and the reason, which is required. */
const SUPPRESSION = /^\s*<!--\s*prose-allow\s+([a-z0-9-]+)\s*:\s*(.+?)\s*-->\s*$/i;

/** The blocks whose text a reader reads as prose. */
const PROSE_BLOCKS = new Set(['paragraph', 'heading', 'tableCell']);

/** The nodes that hold other blocks and therefore have to be walked into. */
const CONTAINERS = new Set([
    'root', 'blockquote', 'listItem', 'list', 'table', 'tableRow',
    'containerDirective', 'leafDirective',
    // A block-level JSX element wraps blocks a reader reads. `<Callout>` around a paragraph
    // renders that paragraph, so the paragraph is walked into like any other.
    'mdxJsxFlowElement',
]);

/** Builds the parser, with MDX only where the file is MDX, since it changes the grammar. */
function processorFor(file) {
    const processor = unified()
        .use(remarkParse)
        .use(remarkFrontmatter, ['yaml'])
        .use(remarkGfm)
        .use(remarkDirective);
    return file.endsWith('.mdx') ? processor.use(remarkMdx) : processor;
}

/**
 * Turns one block into its readable text plus, for every character, where it came from.
 *
 * The map is what lets a match report the author's own line and column rather than an
 * offset into a string this program invented.
 */
function flatten(node) {
    const characters = [];
    const places = [];

    const append = (value, start) => {
        let { line, column } = start;
        for (const character of value) {
            characters.push(character);
            places.push({ line, column });
            if (character === '\n') {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
    };

    const walk = (current) => {
        if (current.type === 'text') {
            append(current.value, current.position.start);
            return;
        }
        if (current.type === 'inlineCode' || current.type === 'html'
            || current.type === 'mdxTextExpression') {
            characters.push(CODE);
            places.push(current.position.start);
            return;
        }
        if (current.type === 'mdxJsxTextElement') {
            // The children of an inline JSX element are what the reader sees; `<Badge>text</Badge>`
            // renders `text`. The attributes are not children in this tree, so walking the
            // children reads the prose without reading the props.
            //
            // An element with no children still stands between the words on either side, so it
            // becomes the sentinel rather than nothing, exactly as inline code does.
            if ((current.children ?? []).length === 0) {
                characters.push(CODE);
                places.push(current.position.start);
                return;
            }
            for (const child of current.children ?? []) {
                walk(child);
            }
            return;
        }
        if (current.type === 'break') {
            append('\n', current.position.start);
            return;
        }
        for (const child of current.children ?? []) {
            walk(child);
        }
    };

    for (const child of node.children ?? []) {
        walk(child);
    }
    return { text: characters.join(''), places };
}

/** One finding, in the shape the report, the linter and the ratchet all read. */
function finding(ruleId, file, place, hit, message, context) {
    return {
        rule: ruleId,
        file,
        line: place?.line ?? 1,
        column: place?.column ?? 1,
        hit,
        message,
        context,
    };
}

/** The words around a match, which is what gives a finding an identity that survives an edit. */
function contextAround(text, index, length) {
    const before = text.slice(Math.max(0, index - 40), index);
    const after = text.slice(index + length, index + length + 40);
    return `${before}${text.substr(index, length)}${after}`.replace(/\s+/g, ' ').trim();
}

/**
 * Whether a match sits inside one of a rule's named exceptions.
 *
 * The exception has to cover the match, not merely appear near it. Testing a window around the
 * hit would let "access is allowed" three words away excuse "the call is blocked", which is a
 * real finding silenced by an unrelated sentence.
 */
function excused(rule, text, index, length) {
    const from = Math.max(0, index - 40);
    const window = text.slice(from, index + length + 40);
    return (rule.allow ?? []).some((exception) => {
        const search = new RegExp(exception.source, exception.flags.replace('g', '') + 'g');
        let match = search.exec(window);
        while (match !== null) {
            const start = from + match.index;
            if (start < index + length && start + match[0].length > index) {
                return true;
            }
            match = search.exec(window);
        }
        return false;
    });
}

/** Every image below a node, whose `alt` is text a reader sees when the image does not load. */
function imagesBelow(node, found = []) {
    for (const child of node.children ?? []) {
        if (child.type === 'image') {
            found.push(child);
        }
        imagesBelow(child, found);
    }
    return found;
}

/** Runs every word rule over one stretch of prose. */
function wordFindings(text, places, file) {
    const found = [];
    for (const rule of [...WORD_RULES, PASSIVE_RULE]) {
        rule.pattern.lastIndex = 0;
        let match = rule.pattern.exec(text);
        while (match !== null) {
            if (!excused(rule, text, match.index, match[0].length)) {
                found.push(finding(
                    rule.id, file, places[match.index], match[0],
                    rule.message(match[0]),
                    contextAround(text, match.index, match[0].length),
                ));
            }
            match = rule.pattern.exec(text);
        }
    }
    return found;
}

/** The abbreviations that end a sentence rather than starting a new one. */
const NOT_A_SENTENCE_END = /\b(?:e\.g|i\.e|etc|cf|vs|approx|Dr|Mr|Ms|Prof|Fig|[A-Z])\.$/;

/** Where each sentence starts in one stretch of prose. */
function sentenceStarts(text) {
    const starts = [0];
    const boundary = /[.!?]["')\]]?\s+/g;
    let match = boundary.exec(text);
    while (match !== null) {
        const upTo = text.slice(0, match.index + 1);
        if (!NOT_A_SENTENCE_END.test(upTo)) {
            starts.push(match.index + match[0].length);
        }
        match = boundary.exec(text);
    }
    return starts;
}

/** Runs the sentence-opener rule, which needs to know where a sentence begins. */
function openerFindings(text, places, file) {
    const found = [];
    for (const start of sentenceStarts(text)) {
        const match = OPENER_RULE.pattern.exec(text.slice(start));
        if (match === null) {
            continue;
        }
        found.push(finding(
            OPENER_RULE.id, file, places[start], match[0],
            OPENER_RULE.message(match[0]),
            contextAround(text, start, match[0].length),
        ));
    }
    return found;
}

/**
 * Runs the sentence-length rule, over the same sentence boundaries the opener rule uses.
 *
 * Words are counted on whitespace, so a flattened code span counts as the one word it stood
 * for rather than as the twelve tokens of a signature nobody wrote as prose.
 */
function lengthFindings(text, places, file) {
    const found = [];
    const starts = sentenceStarts(text);
    for (let index = 0; index < starts.length; index += 1) {
        const start = starts[index];
        const end = index + 1 < starts.length ? starts[index + 1] : text.length;
        const sentence = text.slice(start, end).trim();
        const words = sentence.split(/\s+/).filter((word) => word.length > 0).length;
        if (words <= SENTENCE_LENGTH_RULE.limit) {
            continue;
        }
        found.push(finding(
            SENTENCE_LENGTH_RULE.id, file, places[start], String(words),
            SENTENCE_LENGTH_RULE.message(words),
            contextAround(text, start, Math.min(60, sentence.length)),
        ));
    }
    return found;
}

/** Reads `title` and `description` out of the front matter, which a search result shows. */
function frontMatterFindings(node, file) {
    const found = [];
    const lines = node.value.split('\n');
    lines.forEach((line, offset) => {
        const match = /^(title|description):\s*(.*)$/.exec(line);
        if (match === null) {
            return;
        }
        const value = match[2].trim().replace(/^["']|["']$/g, '');
        const column = line.indexOf(value) + 1;
        const places = Array.from(value, () => ({
            line: node.position.start.line + offset + 1,
            column,
        }));
        found.push(...wordFindings(value, places, file));
        found.push(...openerFindings(value, places, file));
        found.push(...lengthFindings(value, places, file));
    });
    return found;
}

/**
 * Walks the tree, collecting findings and honouring suppressions.
 *
 * A suppression applies to the block directly after it and to nothing else. Anything wider
 * silences text nobody looked at.
 */
function walkBlocks(parent, file, state) {
    let pending = new Map();
    for (const child of parent.children ?? []) {
        if (child.type === 'html' || child.type === 'mdxFlowExpression') {
            const match = SUPPRESSION.exec(child.value ?? '');
            if (match !== null) {
                pending.set(match[1].toLowerCase(), { line: child.position.start.line, reason: match[2] });
                state.declared.push({ rule: match[1].toLowerCase(), file, line: child.position.start.line });
                continue;
            }
        }
        if (child.type === 'yaml') {
            state.findings.push(...frontMatterFindings(child, file));
            continue;
        }

        let produced = [];
        if (PROSE_BLOCKS.has(child.type)) {
            const { text, places } = flatten(child);
            state.prose.push(text);
            produced = [...wordFindings(text, places, file)];
            if (child.type !== 'heading') {
                produced.push(...openerFindings(text, places, file));
                produced.push(...lengthFindings(text, places, file));
                state.body.push({ text, places });
            }
            for (const image of imagesBelow(child)) {
                const alt = image.alt ?? '';
                const places = Array.from(alt, () => image.position.start);
                produced.push(...wordFindings(alt, places, file));
                produced.push(...lengthFindings(alt, places, file));
            }
        }

        for (const item of produced) {
            const suppression = pending.get(item.rule);
            if (suppression === undefined) {
                state.findings.push(item);
            } else {
                state.used.add(`${item.rule}:${suppression.line}`);
            }
        }

        if (CONTAINERS.has(child.type)) {
            walkBlocks(child, file, state);
        }
        pending = new Map();
    }
}

/** Whether a place in a stretch of text sits inside a pair of round brackets. */
function bracketed(text, index) {
    let depth = 0;
    for (let scan = 0; scan < index; scan += 1) {
        if (text[scan] === '(') {
            depth += 1;
        } else if (text[scan] === ')' && depth > 0) {
            depth -= 1;
        }
    }
    return depth > 0;
}

/**
 * The room between an abbreviation and an expansion that follows it immediately.
 *
 * Both orders are correct English: "Java Virtual Machine (JVM)" puts the expansion first, and
 * "JVM (Java Virtual Machine)" puts the abbreviation first and brackets the expansion. The
 * second form leaves the expansion a couple of characters after the abbreviation ends, which is
 * what this allows. Anything further away is an expansion the reader meets too late.
 */
const BRACKET_ROOM = 3;

/**
 * The first use of a word worth spelling out at: outside brackets, and not glued to a hyphen.
 * <p>
 * Expanding inside brackets nests one pair inside another, and `CI/CD` becomes
 * `continuous integration (CI)/CD`. Where every use is bracketed the first one is taken
 * anyway, so the page is still reported rather than silently passing.
 */
function firstPlainUse(body, word) {
    let fallback = null;
    for (const block of body) {
        word.lastIndex = 0;
        let match = word.exec(block.text);
        while (match !== null) {
            if (!bracketed(block.text, match.index)) {
                return { block, index: match.index };
            }
            fallback = fallback ?? { block, index: match.index };
            match = word.exec(block.text);
        }
    }
    return fallback;
}

/**
 * Reports an abbreviation the page never spells out, at the first place worth spelling it out.
 *
 * A use glued to a hyphen does not count, because `in-JVM` expands to `in-Java Virtual
 * Machine (JVM)`, which is not English. The first standalone use is reported instead.
 *
 * Headings neither trigger it nor satisfy it. Spelling a term out inside a heading reads
 * badly, and requiring it there would push authors to reword the heading, which changes its
 * anchor and breaks every link pointing at it.
 */
function abbreviationFindings(body, file) {
    const found = [];
    // The page as one string, with the offset each block starts at, so an expansion and a use
    // can be compared by position rather than only by presence.
    const offsets = [];
    let whole = '';
    for (const block of body) {
        offsets.push(whole.length);
        whole += `${block.text}\n`;
    }
    for (const abbreviation of ABBREVIATIONS) {
        const word = new RegExp(`(?<![\\w-])${abbreviation.short}(?![\\w-])`, 'g');
        const place = firstPlainUse(body, word);
        if (place === null) {
            continue;
        }
        const { block, index } = place;
        const useAt = offsets[body.indexOf(block)] + index;
        const expansion = new RegExp(abbreviation.expansion.source, 'gi');
        const match = expansion.exec(whole);
        if (match !== null && match.index <= useAt + abbreviation.short.length + BRACKET_ROOM) {
            continue;
        }
        found.push(finding(
            ABBREVIATION_RULE.id, file, block.places[index], abbreviation.short,
            match === null
                ? `"${abbreviation.short}" is never spelled out on this page. At its first use `
                    + `write "${abbreviation.write}".`
                : `"${abbreviation.short}" is spelled out only after this, its first use. Move `
                    + `the expansion here and write "${abbreviation.write}".`,
            contextAround(block.text, index, abbreviation.short.length),
        ));
    }
    return found;
}

/** Scans one Markdown or MDX page. */
export async function scanPage(absolute, relative) {
    const source = await readFile(absolute, 'utf8');
    const tree = processorFor(absolute).parse(source);
    const state = { findings: [], prose: [], body: [], declared: [], used: new Set() };
    walkBlocks(tree, relative, state);
    state.findings.push(...abbreviationFindings(state.body, relative));
    return state;
}

/** Scans the `label` of a `_category_.json`, which is the text the sidebar shows. */
export async function scanCategory(absolute, relative) {
    const source = await readFile(absolute, 'utf8');
    const findings = [];
    const match = /"label"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(source);
    if (match === null) {
        return { findings, declared: [], used: new Set() };
    }
    const label = match[1];
    const line = source.slice(0, match.index).split('\n').length;
    const places = Array.from(label, () => ({ line, column: 1 }));
    findings.push(...wordFindings(label, places, relative));
    findings.push(...lengthFindings(label, places, relative));
    return { findings, declared: [], used: new Set() };
}

/**
 * The keys whose string value is text a reader sees, in the site's TypeScript.
 *
 * The navbar, the footer, the tagline and the copyright line are read on every page of the
 * site, so holding the Markdown to the writing rules and leaving these out would hold the
 * rules to whichever file an author happened to open.
 */
const PROSE_KEYS = new Set([
    'label', 'title', 'description', 'tagline', 'copyright', 'alt', 'summary',
]);

/**
 * The components whose children are a code sample rather than a sentence.
 *
 * `<CodeBlock>also</CodeBlock>` puts the word on the page as code, and reporting it would be
 * the Markdown scanner's fenced-block rule broken in the one place it does not apply.
 */
const CODE_ELEMENTS = new Set(['CodeBlock', 'code', 'pre', 'kbd', 'samp']);

/**
 * Turns one string-bearing node into the text a reader sees.
 *
 * `node.text` is the decoded value, so `\'` is already an apostrophe and a rule sees the word
 * the reader sees rather than the escape the author typed. A template's interpolations become
 * a NUL each, exactly as inline code does in Markdown, so no rule matches across a value this
 * file does not contain.
 *
 * Returns null for anything that is not a string, which is how `title: PAGE_TITLE` is skipped:
 * the text lives wherever that constant was written, and this file does not know.
 */
function readableText(ts, node) {
    if (node === undefined) {
        return null;
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
        || ts.isJsxText(node)) {
        return node.text;
    }
    if (ts.isTemplateExpression(node)) {
        return [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(CODE);
    }
    if (ts.isJsxExpression(node)) {
        // Only a quoted string inside the braces is prose. `{value}` is a name, whose text
        // lives wherever it was bound, and a template between tags is a code sample far more
        // often than a sentence, as every snippet on the landing page is.
        return node.expression !== undefined && ts.isStringLiteral(node.expression)
            ? node.expression.text
            : null;
    }
    return null;
}

/**
 * Runs the prose rules over one stretch of text taken from a source file.
 *
 * Every finding in one string is reported at the start of that string rather than at the
 * character it matched. The decoded text and the source are different lengths whenever an
 * escape or an interpolation appears, so a per-character position would be a number this file
 * cannot stand behind. The string is short; the line is enough to find the word.
 */
function sourceFindings(text, place, file, body) {
    if (text.trim().length === 0) {
        return [];
    }
    const places = Array.from(text, () => place);
    // Recorded as a block, so the abbreviation rule can see the page as a whole. Without it a
    // landing page could name an abbreviation the rest of the site is required to spell out.
    body.push({ text, places });
    return [
        ...wordFindings(text, places, file),
        ...openerFindings(text, places, file),
        ...lengthFindings(text, places, file),
    ];
}

/**
 * Scans the text a reader sees inside a TypeScript or TSX file.
 *
 * The file is parsed rather than read lexically. A regex over the raw source cannot tell a
 * comment from a paragraph, a `>` in `left > right` from the end of a tag, or a JSX snippet
 * quoted inside a code sample from the page's own words, and every one of those mistakes
 * reports a violation against something no reader ever sees. The parser knows all of it, and
 * TypeScript is already a dependency of this site.
 *
 * Three kinds of node hold prose: the value of a named property, the value of a named JSX
 * attribute, and the text between two JSX tags. Everything else is code.
 */
export async function scanSource(absolute, relative) {
    const { default: ts } = await import('typescript');
    const source = await readFile(absolute, 'utf8');
    const tree = ts.createSourceFile(absolute, source, ts.ScriptTarget.Latest, true,
        absolute.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const findings = [];
    const body = [];

    const placeOf = (node) => {
        const { line, character } = ts.getLineAndCharacterOfPosition(tree, node.getStart(tree));
        return { line: line + 1, column: character + 1 };
    };

    // The finding is reported where the text is, not where its key is.
    const take = (valueNode) => {
        const text = readableText(ts, valueNode);
        if (text !== null) {
            findings.push(...sourceFindings(text, placeOf(valueNode), relative, body));
        }
    };

    /** The name of a property or attribute, with the quotes off a quoted one. */
    const nameOf = (node) => (node.name === undefined ? undefined : node.name.text);

    /** Whether a node sits inside a component whose children are code. */
    const insideCode = (node) => {
        for (let scan = node.parent; scan !== undefined; scan = scan.parent) {
            if (ts.isJsxElement(scan)
                && CODE_ELEMENTS.has(scan.openingElement.tagName.getText(tree))) {
                return true;
            }
        }
        return false;
    };

    // A visible string is not always behind a key. The landing page holds its feature list in a
    // plain array, and a reader sees every entry, so an array element in a page counts as
    // prose. Configuration files are left to their named keys, where an array holds document
    // identifiers rather than sentences.
    const readsArrays = absolute.endsWith('.tsx');

    const walk = (node) => {
        if ((ts.isPropertyAssignment(node) || ts.isJsxAttribute(node))
            && PROSE_KEYS.has(nameOf(node))) {
            take(node.initializer);
        } else if (ts.isJsxText(node) || ts.isJsxExpression(node)) {
            if (!insideCode(node)) {
                take(node);
            }
        } else if (readsArrays && ts.isArrayLiteralExpression(node)) {
            for (const element of node.elements) {
                take(element);
            }
        }
        node.forEachChild(walk);
    };
    walk(tree);
    findings.push(...abbreviationFindings(body, relative));

    return { findings, prose: [], body, declared: [], used: new Set() };
}

/** Every unknown or unused suppression, which are both mistakes worth failing on. */
export function suppressionProblems(states) {
    const problems = [];
    for (const state of states) {
        for (const declaration of state.declared) {
            if (!RULE_IDS.has(declaration.rule)) {
                problems.push(`${declaration.file}:${declaration.line} suppresses "${declaration.rule}", `
                    + 'which is not a rule.');
            } else if (!state.used.has(`${declaration.rule}:${declaration.line}`)) {
                problems.push(`${declaration.file}:${declaration.line} suppresses "${declaration.rule}", `
                    + 'which the block below it does not break. Remove the suppression.');
            }
        }
    }
    return problems;
}

/** The identity a finding keeps across unrelated edits, which is what the ratchet stores. */
export function identityOf(item) {
    return [item.rule, item.file, item.hit.toLowerCase(), item.context.toLowerCase()].join('␟');
}

/** Where the documentation lives, relative to this file. */
export const DOCS = path.resolve(import.meta.dirname, '..', '..', 'docs');

/** The site root, which holds the standalone pages and the configuration a reader also reads. */
export const SITE = path.resolve(import.meta.dirname, '..', '..');
