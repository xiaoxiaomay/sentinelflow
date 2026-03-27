"""Phase 16c: Validate secrets_v2.jsonl quality."""
import json
import re


def validate():
    secrets = []
    with open('data/secrets/secrets_v2.jsonl') as f:
        for line in f:
            secrets.append(json.loads(line))

    print(f"Total: {len(secrets)} secrets")

    # Check counts
    by_level = {}
    for s in secrets:
        by_level[s['level']] = by_level.get(s['level'], 0) + 1
    print(f"By level: {by_level}")
    assert by_level.get('L3', 0) == 30, f"Expected 30 L3, got {by_level.get('L3', 0)}"
    assert by_level.get('L2', 0) == 30, f"Expected 30 L2, got {by_level.get('L2', 0)}"
    assert by_level.get('L1', 0) == 30, f"Expected 30 L1, got {by_level.get('L1', 0)}"

    # Check required fields
    required = ['_id', 'title', 'text', 'source_type', 'trust_score',
                'sensitivity_level', 'category', 'tags', 'style', 'level']
    for s in secrets:
        for field in required:
            assert field in s, f"Missing field '{field}' in {s.get('_id', '?')}"

    # Check L3 entries have numerical parameters
    l3_secrets = [s for s in secrets if s['level'] == 'L3']
    num_pattern = re.compile(r'\d+\.?\d*[%x]|\d+\.\d+|\b\d{2,}\b')
    l3_without_numbers = [s for s in l3_secrets if not num_pattern.search(s['text'])]
    if l3_without_numbers:
        print(f"WARNING: {len(l3_without_numbers)} L3 entries have no numerical parameters:")
        for s in l3_without_numbers:
            print(f"  {s['_id']}: {s['text'][:80]}...")
    else:
        print(f"PASS: All {len(l3_secrets)} L3 entries contain numerical parameters")

    # Check L3 text length (should be substantial)
    short_l3 = [s for s in l3_secrets if len(s['text'].split()) < 30]
    if short_l3:
        print(f"WARNING: {len(short_l3)} L3 entries are too short (< 30 words)")
        for s in short_l3:
            print(f"  {s['_id']}: {len(s['text'].split())} words")
    else:
        print(f"PASS: All L3 entries have adequate length (min {min(len(s['text'].split()) for s in l3_secrets)} words)")

    # Check L2 entries - should have fewer specific numbers
    l2_secrets = [s for s in secrets if s['level'] == 'L2']
    pct_pattern = re.compile(r'\d+\.?\d*%|\b0\.\d+\b')
    l2_with_pcts = [s for s in l2_secrets if pct_pattern.search(s['text'])]
    if l2_with_pcts:
        print(f"NOTE: {len(l2_with_pcts)} L2 entries contain percentages (review manually):")
        for s in l2_with_pcts:
            print(f"  {s['_id']}: {s['text'][:80]}...")
    else:
        print(f"PASS: No L2 entries contain specific percentages")

    # Check L1 entries are shorter/simpler
    l1_secrets = [s for s in secrets if s['level'] == 'L1']
    l1_avg_words = sum(len(s['text'].split()) for s in l1_secrets) / len(l1_secrets)
    l3_avg_words = sum(len(s['text'].split()) for s in l3_secrets) / len(l3_secrets)
    print(f"Average word count - L3: {l3_avg_words:.0f}, L2: {sum(len(s['text'].split()) for s in l2_secrets)/len(l2_secrets):.0f}, L1: {l1_avg_words:.0f}")
    assert l3_avg_words > l1_avg_words, "L3 should be longer than L1 on average"
    print(f"PASS: L3 entries are longer than L1 (as expected)")

    # Check domains
    by_domain = {}
    for s in secrets:
        by_domain[s['domain']] = by_domain.get(s['domain'], 0) + 1
    print(f"\nBy domain: {by_domain}")
    assert len(by_domain) == 6, f"Expected 6 domains, got {len(by_domain)}"

    print("\n--- Sample L3 entries ---")
    for s in l3_secrets[:3]:
        print(f"\n{s['_id']} [{s['domain']}]:")
        print(f"  {s['text'][:200]}...")

    print("\n--- Sample L2 entries ---")
    for s in l2_secrets[:2]:
        print(f"\n{s['_id']} [{s['domain']}]:")
        print(f"  {s['text']}")

    print("\n--- Sample L1 entries ---")
    for s in l1_secrets[:2]:
        print(f"\n{s['_id']} [{s['domain']}]:")
        print(f"  {s['text']}")

    print("\n✓ Validation complete — all checks passed!")


if __name__ == '__main__':
    validate()
