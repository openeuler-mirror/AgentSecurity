"""Lossless, order-independent identities for the complete build input."""
import hashlib
import json

from .prefilter_contract import MAX_RULES, MAX_SNAPSHOT_BYTES, RuleSpec, rule_key
from .prefilter_manifest import PackageError, encode_rule_pattern

FINGERPRINT_VERSION = 1


def fixed_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def canonical_rules(rules):
    unique = {}
    size = 0
    for index, rule in enumerate(rules):
        if index >= MAX_RULES or not isinstance(rule, RuleSpec):
            raise PackageError('invalid or oversized rule snapshot')
        pattern, flags = rule_key(rule.pattern, rule.flags)
        pattern = str.__str__(pattern)
        record = fixed_json([encode_rule_pattern(pattern), flags])
        size += len(pattern.encode('utf-8', 'surrogatepass'))
        if size > MAX_SNAPSHOT_BYTES:
            raise PackageError('source snapshot exceeds byte budget')
        unique[record] = RuleSpec(pattern, flags)
    return tuple(unique[key] for key in sorted(unique))


def rules_fingerprint(rules):
    records = [[encode_rule_pattern(r.pattern), r.flags] for r in canonical_rules(rules)]
    return hashlib.sha256(fixed_json({
        'fingerprint_version': FINGERPRINT_VERSION, 'rules': records})).hexdigest()
