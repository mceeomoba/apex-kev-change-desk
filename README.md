# Apex KEV Change Desk

An offline change-review prototype for IT teams comparing two CISA Known Exploited Vulnerabilities (KEV) JSON snapshots. It reports added, removed and edited records, including exact before/after values for every changed field. It is a data-review utility, not a security assessment.

**Free prototype. No customers, paid service or demand validation claimed. Developed with AI assistance. Not affiliated with or endorsed by CISA.**

## Try it and share workflow feedback

Run the synthetic example below, or compare two saved public catalog snapshots. [Share workflow feedback](https://github.com/mceeomoba/apex-kev-change-desk/issues/1): what review task were you trying to finish, and did this remove a manual step? Feedback is public and exposes your GitHub identity. Do not include private asset inventories, client names, credentials or incident details. Posted for the Apex project; AI-assisted prototype and feedback collection. No paid pilot or response-time promise.

Input limit: decimal and exponent-form JSON numbers are rejected, including in extension fields. Integer numbers are retained exactly. Future schemas are not guaranteed to work. Do not modify source values to bypass this limit.

## Run

Python 3.10 or newer. Standard library only. No account or installation needed.

```sh
python3 kev_diff.py examples/before.json examples/after.json > review.json
python3 kev_diff.py examples/before.json examples/after.json --vendor 'Example Vendor' > vendor-review.json
python3 kev_diff.py examples/before.json examples/after.json --format markdown > review.md
python3 -m unittest discover -s tests -v
```

The example catalog is **synthetic**, not a current vulnerability feed. It shows one addition, one edited record and one removal. The edited record changes a due date and an unknown extension field. Nothing runs in the background.

For real data, download and retain successive JSON snapshots yourself from the [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or its [official mirror](https://github.com/cisagov/kev-data). Check provenance and download dates. Pass the earlier snapshot first. This tool does not fetch sources, establish authenticity, tell whether a catalog is complete, or claim to be current. File SHA-256 values support reproducibility, not authentication.

## Reading the output

JSON is the default. `--format markdown` produces a human-readable review with counts, snapshot provenance, limits, metadata changes and each complete before/after record for matching changes. It does not add analysis or change the comparison. Source values stay in JSON code blocks; a dynamically sized fence prevents embedded backticks from escaping those blocks in ordinary Markdown renderers, not every viewer. Open the Markdown in a viewer you trust. Review reports before sharing: full before/after records for matching changes, metadata changes and vendor filters are included. Keep `markdown_report.py` alongside `kev_diff.py` for this optional format.

## What the report means

- `added`: CVE ID present only in the supplied after file.
- `removed`: CVE ID present only in the before file. **Not proof of remediation or safety.** A partial after file can cause many apparent removals.
- `changed`: at least one record field differs. Before and after values, field-presence flags and full records are retained.
- Fields unknown to this version are preserved and compared. Object key order is ignored; array order is significant.
- Catalog-level metadata changes are reported separately, even with a vendor filter.
- `--vendor` is an exact, case-insensitive match on `vendorProject`, against either snapshot. It is not fuzzy matching or installed-product detection. Omitting it compares the full supplied catalog.
- Zero record changes is not proof that no vulnerability exists. A later feed can retain the same records.
- Dates and source actions are copied as data. CISA due dates are not universal customer deadlines. Follow authoritative vendor guidance and applicable rules for your organization.

**Never redirect output onto either input file.** For example, `> before.json` truncates that source before Python can read it. Use a new output filename.

Exit 0 means a valid comparison was produced, including a no-change result. Exit 2 means invalid input or a file error; no report is emitted by the program. If you use shell redirection, your shell may create an empty output file even on error, so check the exit code before replacing a prior report.

## Privacy and limits

All file processing is local. No network requests, telemetry, storage account, automated alerts, scanning, exploitation, remediation or store integration. Files you save remain on your device. Reports contain the supplied records and vendor filters; review them before sharing. Maximum input size is 20 MB per file. Invalid UTF-8, duplicate JSON keys/IDs, invalid dates, mismatched counts and reversed release timestamps are rejected. Unknown fields are preserved, not schema-validated. Decimal and exponent-form JSON numbers anywhere in a snapshot are explicitly rejected, including extension fields, to avoid silently rounding values. Integer JSON numbers are retained exactly. Do not modify source values to bypass this limit. This trades forward compatibility for exactness: a future official feed with decimal/exponent values will be rejected until support is added. Required fields follow the current official schema, but this is not a complete JSON Schema implementation.

## Verification

43 synthetic tests pass. On October 14, 2026, the prototype loaded the official mirror snapshot with catalogVersion `2026.10.13`, 1,741 entries and dateReleased `2026-10-13T19:10:43.6568Z`. Comparing that snapshot to itself returned zero record changes. This proves input compatibility with that one snapshot only, not authenticity, exposure, or correct handling of two successive real feeds. Its SHA-256 was `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`.

## Alternatives and business status

CISA already provides a free catalog. Its official repository README links an [interactive commit-change dashboard](https://cisagov.github.io/kev-data/). Other open-source diff and monitoring tools exist. This prototype explores a narrow offline, field-level review workflow. No claim of a unique market, merchant validation, security certification, paid alert service or willingness to pay is made. Any future managed delivery or paid product would require separate validation and operational controls.

## Sources

- [Official CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): authoritative source and prioritization input.
- [Official CISA data mirror](https://github.com/cisagov/kev-data): downloadable JSON, schema, history, dashboard and CC0 data license. Source data remains under its own terms. This release bundles synthetic records only.
- [myseq/cisa_kev_utils](https://github.com/myseq/cisa_kev_utils): existing daily snapshots and diff utilities.
- [hahwul/kev.cr](https://github.com/hahwul/kev.cr): existing parsing/query/diff library.
- [quantumcore/kev_monitor](https://github.com/quantumcore/kev_monitor): existing change monitor with desktop notifications.

## License

Prototype source code: MIT, see LICENSE. No CISA logo, seal or endorsement is used.
