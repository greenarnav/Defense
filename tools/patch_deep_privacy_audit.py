#!/usr/bin/env python3
from pathlib import Path

# The patch is deterministic; this revision also retriggers the evidence workflow
# after a transient GitHub release-asset connection reset.
path = Path('tools/deep_privacy_audit.py')
text = path.read_text(encoding='utf-8')
replacements = {
    'fb_reachable = any(any(c["first_party"] for c in d["callers"]) or d["caller_chains"] for d in fb_init_defs)':
        'fb_reachable = any(any(c["first_party"] for c in d["callers"]) or any(len(chain) > 1 and any("Lcom/callapp/" in step for step in chain[:-1]) for chain in d["caller_chains"]) for d in fb_init_defs)',
    'inmobi_reachable = any(any(c["first_party"] for c in d["callers"]) or d["caller_chains"] for d in inmobi_defs)':
        'inmobi_reachable = any(any(c["first_party"] for c in d["callers"]) or any(len(chain) > 1 and any("Lcom/callapp/" in step for step in chain[:-1]) for chain in d["caller_chains"]) for d in inmobi_defs)',
    'applovin_reachable = any(d["callers"] or d["caller_chains"] for d in applovin_init_defs)':
        'applovin_reachable = any(any(c["first_party"] for c in d["callers"]) or any(len(chain) > 1 and any("Lcom/callapp/" in step for step in chain[:-1]) for chain in d["caller_chains"]) for d in applovin_init_defs)',
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f'Expected source line missing: {old}')
    text = text.replace(old, new)
path.write_text(text, encoding='utf-8')
print('Applied strict first-party reachability patch')
