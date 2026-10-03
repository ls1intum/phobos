# The writing rules

The rules this documentation is held to, and the line between the ones a machine may decide and
the ones it may not.

They are the AET general writing rules, carried over from the
[Ares 2 documentation](https://ls1intum.github.io/Ares2/contributor/writing-rules) so that the
two sister sites read alike. Two are retargeted for this repository: the canonical term for the
thing inside the sandbox is "the sandboxed command", and the abbreviation list is the one these
pages use.

`scripts/prose/rules.mjs` is the implementation, and `scripts/prose/prose.test.mjs` holds this
document and that file to each other: a rule promoted in the code and left in the wrong table
here fails `pnpm run test:prose`. **Changing a rule's level is therefore a change to this
document, in the same commit.**

```bash
pnpm run lint:prose     # fails on an enforced finding nobody has accepted
pnpm run report:prose   # every finding, enforced and advisory, as JSON
pnpm run prose:accept   # rewrite the baseline and the advisory ceilings
```

## Enforced rules

A rule may only be enforced where its forbidden form is decidable from the text alone, without
knowing what the author meant. `doesn't` is always a contraction; there is no sentence in which
it is not.

| Rule | What it refuses | Write instead |
| --- | --- | --- |
| `no-contractions` | `doesn't`, `it's`, `you're`, with either apostrophe | the words in full |
| `no-american-spellings` | a spelling whose British form never depends on the sentence | the British form the message names |
| `no-always-filler` | `also`, `actually`, `additional`, `additionally`, `of course`, `furthermore`, `moreover`, `obviously`, `clearly` | `and` for another entry, `further` for one more, `as well` for an addition, or nothing |
| `canonical-terms` | `graded`, `restricted`, `supervised` or `confined` followed by `code`, `command` or `program` | `the sandboxed command` |
| `no-back-loaded-opener` | a sentence opening with `As`, `Since`, `To`, `In order to` or `Because` | the subject first |
| `abbreviation-first-use` | an abbreviation used on a page that never spells it out | the expansion followed by the abbreviation in brackets |

`no-american-spellings` is deliberately not "British English", which is not decidable: `licence`
and `license` are both British and differ by part of speech, and `program` is the correct
British spelling for software.

`canonical-terms` exists because Phobos sandboxes any executable program and the documentation
says so. A page that discusses grading still names a student submission, because that is the use
case rather than a second name for the concept.

## Advisory rules

An advisory rule is reported and never fails on its own. `may` is permission, possibility or
uncertainty depending on the sentence around it, and "the analysis may report false positives"
is correct English that a lexical rule cannot tell from a violation. Turning that into `must`
would state a guarantee the code does not make, which in documentation for a security tool is
worse than the style problem it fixes.

Each advisory rule has a **ceiling** in `scripts/prose/advisory-ceiling.json`: the number of
findings it is allowed. The ratchet fails in **both** directions, which is the part that
surprises people. A count above its ceiling fails, and so does a count below it: improving the
prose means re-recording the smaller number with `pnpm run prose:accept` in the same commit.
A ceiling that stayed at the old figure would leave room for the next change to spend, which is
the drift the ceiling exists to prevent.

| Rule | What it reports | When to leave it |
| --- | --- | --- |
| `prefer-must` | `should`, `may` | where the sentence describes a possibility rather than an obligation |
| `present-tense` | `will`, `would` | where the sentence is a counterfactual |
| `context-filler` | `just`, `simply`, `basically`, `essentially`, `in fact` | where `just` means "a moment ago" |
| `address-the-reader` | `we`, `our`, `ours`, `us` | where it means the Phobos project itself |
| `no-intensifiers` | `very`, `extremely`, `highly`, `really`, `quite`, `optimal`, `optimally`, `best`, `greatest`, `worst`, `perfect`, `perfectly` | where the word is part of a term of art |
| `active-voice` | a finite form of "to be" plus a participle | where the actor is genuinely unknown, or the participle is an adjective |
| `long-sentence` | a sentence past 35 words | where splitting it would break the argument |

## Rules with no check, and why

The general rules ask for several things no scanner can decide. They are the standard all the
same, and a reviewer is what enforces them.

| The rule | Why nothing checks it |
| --- | --- |
| Put the verb early in the sentence | Deciding where the verb is needs a parser for English, and a wrong answer would report sentences nobody wrote. The sentence-length rule is the measurable half. |
| One idea per paragraph | Counting ideas is the whole problem. |
| Say "you", meaning the reader | The first-person rule catches `we` and cannot tell a missing "you" from a sentence that needs none. |
| Prefer the concrete noun to the abstract one | The list of abstract nouns is a dictionary this repository would then maintain. |
| Explain a term before using it | The abbreviation rule covers abbreviations, which are the decidable part. A term of art spelled out in words is not. |
| Do not repeat what the previous sentence said | Deciding this needs the two sentences read against each other. |

## Suppressing a finding

A suppression is an HTML comment naming the rule and the reason, on the line before the
finding:

```markdown
<!-- prose-allow prefer-must: this sentence describes a possibility, not a guarantee -->
```

The reason is required, and a suppression that names no rule, or silences nothing, fails
`pnpm run lint:prose` exactly as a finding does.

## The baseline

`scripts/prose/baseline.json` records the enforced findings accepted for now. It is a ratchet
keyed on the identity of a finding, not on a count per file: a count lets one violation replace
another and stay green. The identity is the rule, the file, the words matched and the words
around them, never a line number, because an unrelated edit above moves every line below it.

The list may only shrink. `pnpm run lint:prose` fails when an accepted finding has been fixed
and the smaller baseline has not been committed, for the same reason the ceilings fail when
they are looser than the truth.

`scripts/prose/rules.mjs` holds the full pattern for each rule. The word lists above name what
a reader hits most often rather than every form the pattern matches.
