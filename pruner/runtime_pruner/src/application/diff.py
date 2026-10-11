"""What a policy lacks for recorded sessions, and what it grants that no session used (plan A.12).

The comparison changes nothing and writes no file: it is the input for a person who tightens a shipped
base policy or checks that an exercise policy covers what its reference program does. A base entry an
ancestor already covers is marked and never called unused, because removing it changes which
exercise configurations Phobos accepts (AGENTS.md).
"""

from __future__ import annotations

import dataclasses
import os

from runtime_pruner.src.application import generate
from runtime_pruner.src.domain import endpoints
from shared.src.domain import cfgfile, network

# The loopback wildcards and the address families each covers.
LOOPBACK_WILDCARDS = {"allow 127.0.0.1:*": frozenset({"inet"}), "allow [::1]": frozenset({"inet6"}),
                      "allow localhost": frozenset({"inet", "inet6"})}


@dataclasses.dataclass(frozen=True)
class Report:
    """The result: needs no rule covers, rules no session used, and rules an ancestor already covers."""

    missing: list[str]
    unused: list[str]
    covered_by_ancestor: list[str]


def compare(recordings: list[generate.Recording], policy: cfgfile.Policy) -> Report:
    """The needs of the recordings against the policy.

    A filesystem need is covered when the rights of every rule at or above its path (Landlock unions
    them) hold the rights of its section, with the policy's own paths and the needs' paths resolved
    through symbolic links, so both spellings of a link fold. A network rule is covered when the same
    rule, or a loopback wildcard of its transport and address family, is in the policy; only exact rules
    and the loopback wildcards are matched, so a range or a wildcard host is never called unused.
    """
    sessions = [session for recording in recordings for session in recording.sessions]
    folded = _folded(policy)
    all_needs = [need for session in sessions for need in session.needs.needs]
    missing = sorted({f"[{section}] {path}" for need in all_needs for path in need.objects for section in need.sections
                      if not cfgfile.SECTION_RIGHTS[section] <= cfgfile.covered_rights(path, folded)})
    unused: list[str] = []
    covered: list[str] = []
    for path, sections in sorted(folded.fs.items()):
        for section in sorted(sections):
            row = f"[{section}] {path}"
            if _covered_by_ancestor(path, section, folded):
                covered.append(row)
            elif not _used(path, section, all_needs):
                unused.append(row)
    network_rules = endpoints.rules([session.network for session in sessions], sessions[0].hosts if sessions else {})
    generated = [rule.text for rule in (*network_rules.connect, *network_rules.bind) if not cfgfile.is_comment_rule(rule)]
    granted = {*policy.connect, *policy.bind}
    missing.extend(f"[{_section_of(rule, network_rules)}] {rule}" for rule in generated
                   if not _admitted(rule, granted))
    unused.extend(f"[connect] {rule}" for rule in policy.connect if _comparable(rule) and not _requested(rule, generated))
    unused.extend(f"[bind] {rule}" for rule in policy.bind if _comparable(rule) and rule not in generated)
    return Report(missing=sorted(set(missing)), unused=unused, covered_by_ancestor=covered)


def render(report: Report) -> str:
    """The report as text: three lists, one row per line, each list headed by what it holds."""
    blocks = [("Needed by a session, not granted by the policy", report.missing),
              ("Granted by the policy, used by no session", report.unused),
              (("Granted by the policy, covered by an ancestor entry (removing it changes which exercise "
                "configurations are accepted)"), report.covered_by_ancestor)]
    return "\n\n".join("\n".join([f"{title}: {len(rows)}", *(f"  {row}" for row in rows)]) for title, rows in blocks) + "\n"


def _folded(policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy with every filesystem path resolved through symbolic links and entries on one target united."""
    fs: dict[str, frozenset[str]] = {}
    for path, sections in policy.fs.items():
        target = os.path.realpath(path)
        fs[target] = fs.get(target, frozenset()) | sections
    return dataclasses.replace(policy, fs=fs)


def _covered_by_ancestor(path: str, section: str, policy: cfgfile.Policy) -> bool:
    """Whether the rules strictly above the path already grant the section's rights."""
    above = frozenset().union(*(cfgfile.rights_of(sections) for other, sections in policy.fs.items()
                                if cfgfile.is_beneath(path, other)))
    return cfgfile.SECTION_RIGHTS[section] <= above


def _used(path: str, section: str, all_needs: list) -> bool:
    """Whether some need at or beneath the path asks for rights the section grants."""
    rights = cfgfile.SECTION_RIGHTS[section]
    return any(rights & cfgfile.rights_of(need.sections) for need in all_needs
               for item in need.objects if item == path or cfgfile.is_beneath(item, path))


def _admitted(rule: str, granted: set[str]) -> bool:
    """Whether a generated rule is in the granted rules, or a loopback wildcard of its transport covers it."""
    if rule in granted:
        return True
    marker = " udp" if rule.endswith(" udp") else ""
    body = rule.removesuffix(marker)
    kind = network.loopback_kind(_host(body))
    if kind is None:
        return False
    return any(kind in families and wildcard + marker in granted for wildcard, families in LOOPBACK_WILDCARDS.items())


def _host(rule: str) -> str:
    """The host a rule names: the text between `allow ` and the port, an IPv6 address without its brackets."""
    text = rule.removeprefix("allow ")
    if text.startswith("["):
        return text[1:text.index("]")]
    return text.rsplit(":", 1)[0] if ":" in text else text


def _comparable(rule: str) -> bool:
    """Whether a rule can be compared with a recorded endpoint: an exact address or name and port, or a loopback wildcard.

    A range (`192.0.2.0/24:80`), a wildcard host or a wildcard port is not compared, so it is never
    reported as unused.
    """
    bare = rule.removesuffix(" udp")
    return bare in LOOPBACK_WILDCARDS or not (bare.endswith(":*") or any(mark in _host(bare) for mark in "/*"))


def _requested(rule: str, generated: list[str]) -> bool:
    """Whether some generated rule is this rule, or this rule is a loopback wildcard that covers one."""
    if rule in generated:
        return True
    return any(_admitted(item, {rule}) for item in generated)


def _section_of(rule: str, rules: endpoints.NetworkRules) -> str:
    """connect or bind, by which list of the network rules holds the generated rule."""
    return "bind" if any(item.text == rule for item in rules.bind) else "connect"
