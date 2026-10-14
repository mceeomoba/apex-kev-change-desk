"""Render KEV review data as Markdown, keeping all source values in code blocks."""
import json

def block(value):
    # JSON escapes embedded controls. A fence longer than every source backtick run
    # prevents untrusted catalog text from breaking into active Markdown/HTML.
    text = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
    longest = max((len(run) for run in __import__('re').findall(r'`+', text)), default=0)
    fence = '`' * max(3, longest + 1)
    return fence + 'json\n' + text + '\n' + fence + '\n'

def render_markdown(report):
    sections = [
        '# Apex KEV change review\n',
        'Offline snapshot comparison. Not a security assessment. No background monitoring.\n',
        '## Result\n',
        f"Added: {report['summary']['added']} | Changed: {report['summary']['changed']} | Removed: {report['summary']['removed']}\n",
        'These counts describe the supplied files and vendor filter only. No changes is not proof of no vulnerabilities.\n',
        '## Snapshot provenance\n',
        block({'before': report['before'], 'after': report['after'],
               'sourceReference': report['sourceReference'], 'sourceFetchedByTool': report['sourceFetchedByTool'],
               'vendorFilter': report['vendorFilter'], 'filterMode': report['filterMode']}),
        'Hashes support reproducibility, not authenticity. Source text below is data, not instructions.\n',
        '## Limits\n',
    ]
    sections.extend('- ' + warning + '\n' for warning in report['warnings'])
    sections += ['\n## Catalog metadata changes\n', block(report['catalogMetadataChanges']), '## Record changes\n']
    if not report['changes']:
        sections.append('No record changes matched this comparison. Check the file dates, completeness and filter before interpreting that result.\n')
    for row in report['changes']:
        # Validated identifiers and fixed kinds are the only source data in headings.
        sections.append(f"### {row['cveID']} ({row['kind']})\n")
        sections.append(block({'fields': row['fields'], 'before': row['before'], 'after': row['after']}))
    return '\n'.join(sections)
