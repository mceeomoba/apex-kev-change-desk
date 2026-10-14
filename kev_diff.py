#!/usr/bin/env python3
"""Offline CISA KEV snapshot comparison. No network, scanning or system changes."""
import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime
from fractions import Fraction
from pathlib import Path

MAX_BYTES = 20_000_000
REQUIRED = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
            'shortDescription', 'requiredAction', 'dueDate')
SOURCE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'

class InvalidCatalog(ValueError):
    pass

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidCatalog('Duplicate JSON key: ' + key)
        result[key] = value
    return result

def invalid_constant(value):
    raise InvalidCatalog('Non-JSON number: ' + value)

def unsupported_float(value):
    raise InvalidCatalog('Decimal or exponent JSON numbers are unsupported; use unmodified catalogs with integer numbers only')

def check_numbers(value):
    if isinstance(value, float):
        raise InvalidCatalog('Decimal or exponent JSON numbers are unsupported')
    if isinstance(value, dict):
        for child in value.values():
            check_numbers(child)
    elif isinstance(value, list):
        for child in value:
            check_numbers(child)

def load_catalog(path):
    path = Path(path)
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InvalidCatalog('Catalog exceeds 20 MB limit')
    text = data.decode('utf-8-sig', errors='strict')
    obj = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant, parse_float=unsupported_float)
    validate(obj)
    return obj, hashlib.sha256(data).hexdigest()

def iso_date(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        raise InvalidCatalog(name + ' must be YYYY-MM-DD')
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise InvalidCatalog(name + ' is not a valid calendar date') from error

def release_time(value):
    if not isinstance(value, str):
        raise InvalidCatalog('dateReleased must be a string')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]+))?(Z|[+-]\d{2}:\d{2})', value)
    if not match:
        raise InvalidCatalog('dateReleased must be an ISO timestamp with timezone')
    try:
        parsed = datetime.fromisoformat(match[1] + match[3].replace('Z', '+00:00'))
        seconds = parsed.toordinal() * 86400 + parsed.hour * 3600 + parsed.minute * 60 + parsed.second - int(parsed.utcoffset().total_seconds())
        return Fraction(seconds) + Fraction('0.' + (match[2] or '0'))
    except (ValueError, OverflowError, OSError) as error:
        raise InvalidCatalog('dateReleased must be a valid ISO timestamp') from error

def validate(obj):
    check_numbers(obj)
    if not isinstance(obj, dict):
        raise InvalidCatalog('Catalog must be an object')
    if not isinstance(obj.get('catalogVersion'), str) or not obj['catalogVersion'].strip():
        raise InvalidCatalog('catalogVersion must be a nonempty string')
    release_time(obj.get('dateReleased'))
    rows = obj.get('vulnerabilities')
    if not isinstance(rows, list):
        raise InvalidCatalog('vulnerabilities must be an array')
    if type(obj.get('count')) is not int or obj['count'] != len(rows):
        raise InvalidCatalog('count must equal the number of vulnerabilities')
    ids = set()
    for row in rows:
        if not isinstance(row, dict):
            raise InvalidCatalog('Each vulnerability must be an object')
        for field in REQUIRED:
            if not isinstance(row.get(field), str):
                raise InvalidCatalog('Missing or non-string required field: ' + field)
        cve = row['cveID']
        if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}', cve):
            raise InvalidCatalog('Invalid CVE ID: ' + cve)
        if cve in ids:
            raise InvalidCatalog('Duplicate CVE ID: ' + cve)
        ids.add(cve)
        iso_date(row['dateAdded'], 'dateAdded')
        iso_date(row['dueDate'], 'dueDate')
        for field in ('knownRansomwareCampaignUse', 'forensicTriage', 'notes'):
            if field in row and not isinstance(row[field], str):
                raise InvalidCatalog(field + ' must be a string')
        if 'cwes' in row and (not isinstance(row['cwes'], list) or any(
            not isinstance(cwe, str) or not re.fullmatch(r'CWE-[0-9]+', cwe) for cwe in row['cwes'])):
            raise InvalidCatalog('cwes must be an array of CWE IDs')
    return obj

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)

def compare(before, after, before_hash=None, after_hash=None, vendors=()):
    validate(before)
    validate(after)
    if release_time(before['dateReleased']) > release_time(after['dateReleased']):
        raise InvalidCatalog('Before snapshot is newer than after snapshot')
    old = {row['cveID']: row for row in before['vulnerabilities']}
    new = {row['cveID']: row for row in after['vulnerabilities']}
    selected = {vendor.casefold() for vendor in vendors}
    changes = []
    for cve in sorted(set(old) | set(new)):
        a, b = old.get(cve), new.get(cve)
        if selected and not any(row and row['vendorProject'].casefold() in selected for row in (a, b)):
            continue
        if a is not None and b is not None and canonical(a) == canonical(b):
            continue
        fields = []
        if a is not None and b is not None:
            for key in sorted(set(a) | set(b)):
                if key not in a or key not in b or canonical(a[key]) != canonical(b[key]):
                    fields.append({'field': key, 'beforePresent': key in a, 'afterPresent': key in b,
                                   'before': a.get(key), 'after': b.get(key)})
        changes.append({'cveID': cve, 'kind': 'added' if a is None else 'removed' if b is None else 'changed',
                        'fields': fields, 'before': a, 'after': b})
    meta_changes = []
    for key in sorted((set(before) | set(after)) - {'vulnerabilities'}):
        if key not in before or key not in after or canonical(before[key]) != canonical(after[key]):
            meta_changes.append({'field': key, 'beforePresent': key in before, 'afterPresent': key in after,
                                 'before': before.get(key), 'after': after.get(key)})
    return {'reportVersion': 1, 'sourceReference': SOURCE, 'sourceFetchedByTool': False,
            'before': {'catalogVersion': before['catalogVersion'], 'dateReleased': before['dateReleased'],
                       'count': before['count'], 'sha256': before_hash},
            'after': {'catalogVersion': after['catalogVersion'], 'dateReleased': after['dateReleased'],
                      'count': after['count'], 'sha256': after_hash},
            'vendorFilter': list(vendors), 'filterMode': 'exact case-insensitive, either snapshot',
            'summary': {kind: sum(c['kind'] == kind for c in changes) for kind in ('added', 'changed', 'removed')},
            'catalogMetadataChanges': meta_changes, 'changes': changes,
            'warnings': ['User-supplied snapshots; their authenticity and completeness are not verified.',
                         'Not a scanner, exposure assessment, patch verification or compliance decision.',
                         'Removed means absent from the supplied after snapshot, not fixed or safe.',
                         'CISA dueDate is preserved source data, not a universal deadline.',
                         'A comparison with no changes is not proof that no vulnerabilities exist. This tool does not perform background monitoring.']}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', help='Earlier official-format JSON snapshot')
    parser.add_argument('after', help='Later official-format JSON snapshot')
    parser.add_argument('--format', choices=('json', 'markdown'), default='json', help='Output format; JSON by default')
    parser.add_argument('--vendor', action='append', default=[], help='Exact vendorProject, case-insensitive; repeatable')
    args = parser.parse_args(argv)
    try:
        if any(not vendor.strip() for vendor in args.vendor):
            raise InvalidCatalog('Vendor filter cannot be blank')
        before, before_hash = load_catalog(args.before)
        after, after_hash = load_catalog(args.after)
        report = compare(before, after, before_hash, after_hash, args.vendor)
        # Encode completely before writing stdout, so encoding errors do not emit a partial report.
        if args.format == 'markdown':
            from markdown_report import render_markdown
            output = render_markdown(report)
        else:
            output = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + '\n'
        encoded = output.encode('utf-8')
        sys.stdout.buffer.write(encoded)
        return 0
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        print('Input error: ' + str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
