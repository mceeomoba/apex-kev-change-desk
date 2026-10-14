# Reproduce a real KEV field change

Posted for the Apex project. AI-assisted prototype and technical verification. This is a worked example, not a live alert, security assessment or evidence of customer use.

A KEV record can change without its CVE ID being new. In two official-source snapshots checked on October 14, 2026, CVE-2026-12569 kept its identifier while `forensicTriage` changed from `No` to `Yes`. A list of newly added IDs alone would miss that edit. The field is preserved source data; this guide does not decide which rule applies to your organization or what systems are exposed.

## Source pair

Official source repository: https://github.com/cisagov/kev-data

| Snapshot | Commit | Entries | File SHA-256 |
| --- | --- | ---: | --- |
| Earlier | `be330da604b41a3b29c84b3f0a0122d6d2167417` | 1,739 | `fb1621beec7db19d99c1f919dede3d4cc01ad88acd16f79f1592929c4826dfee` |
| Later | `f14dde8787ac19895e467fbbcb5494269367c2e5` | 1,740 | `bf25dac3bd410db5fb5e0fd406a2ebf626693d97619848b17b796d6c737d23d5` |

The comparison found one addition, CVE-2026-104935, and one edited record, CVE-2026-12569. No removals. An independent checker enumerated all IDs and compared complete records; its counts, changed field and retained values agreed with the prototype. This tests one transition, not every feed or future schema.

## Reproduce locally

Inspect and trust the repository code before executing it. Python 3.10+ and Git are required. These commands download public code/data. The comparison itself has no network calls. Run in a new empty directory; do not reuse source/output paths containing work you need to keep.

```sh
git clone https://github.com/mceeomoba/apex-kev-change-desk.git
git -C apex-kev-change-desk checkout 217c911e7dc216c1c7dded1f01a4076fde4fddd2
git clone https://github.com/cisagov/kev-data.git cisa-kev-source
git -C cisa-kev-source show be330da604b41a3b29c84b3f0a0122d6d2167417:known_exploited_vulnerabilities.json > before.json
git -C cisa-kev-source show f14dde8787ac19895e467fbbcb5494269367c2e5:known_exploited_vulnerabilities.json > after.json
sha256sum before.json after.json
# macOS alternative: shasum -a 256 before.json after.json
# Compare both values with the table above before running the tool.
python3 apex-kev-change-desk/kev_diff.py before.json after.json > transition-review.json
python3 apex-kev-change-desk/kev_diff.py before.json after.json --format markdown > transition-review.md
```

The tool checkout is pinned to `217c911e7dc216c1c7dded1f01a4076fde4fddd2`, the source version used for this guide. Compare both printed snapshot hashes with the listed values before running the comparison. If either differs, stop and investigate rather than editing a source value to match expectations. Hashes are integrity aids, not authentication.

Check each command's exit status before continuing. A shell can create an empty redirected output file even when a command fails. Never redirect output onto either source file. Open Markdown only in a viewer you trust; code fences protect ordinary renderers, not every viewer. Full before/after records for matching changes, catalog metadata changes and vendor filters are included, so review outputs before sharing.

## Limits

- A record's absence from a supplied after snapshot is not proof of remediation or safety.
- A comparison with no changes is not proof that no vulnerabilities exist. This tool does not perform background monitoring.
- Source hashes aid reproducibility, not source authentication. Validate source provenance separately.
- Counts depend on file completeness and filters. No installed-product, asset or version matching is performed.
- Decimal/exponent JSON numbers are rejected to avoid rounding; integers are exact. Future schemas are not guaranteed to work. Do not modify official data to bypass a rejection.
- CISA's free catalog, schema, history and dashboard already exist. The prototype is an optional offline review utility, not a substitute for authoritative guidance.

Workflow feedback belongs in the public project issue: https://github.com/mceeomoba/apex-kev-change-desk/issues/1. Issues expose the author's GitHub identity. Do not include private inventories, client names, credentials or incident information. No paid pilot or response-time promise.
