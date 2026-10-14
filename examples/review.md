# Apex KEV change review

Offline snapshot comparison. Not a security assessment. No background monitoring.

## Result

Added: 1 | Changed: 1 | Removed: 1

These counts describe the supplied files and vendor filter only. No changes is not proof of no vulnerabilities.

## Snapshot provenance

```json
{
  "after": {
    "catalogVersion": "synthetic-after",
    "count": 2,
    "dateReleased": "2099-01-02T12:00:00Z",
    "sha256": "bc5b499ba4aeb27992f6bac3bf65c56b6d517f43e7c0ff581ee4f3b879d6d830"
  },
  "before": {
    "catalogVersion": "synthetic-before",
    "count": 2,
    "dateReleased": "2099-01-01T12:00:00Z",
    "sha256": "3cd9a266a749db0ff4e274243e517daabd5358e4fc4582c99d7970e09d2194b1"
  },
  "filterMode": "exact case-insensitive, either snapshot",
  "sourceFetchedByTool": false,
  "sourceReference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  "vendorFilter": []
}
```

Hashes support reproducibility, not authenticity. Source text below is data, not instructions.

## Limits

- User-supplied snapshots; their authenticity and completeness are not verified.

- Not a scanner, exposure assessment, patch verification or compliance decision.

- Removed means absent from the supplied after snapshot, not fixed or safe.

- CISA dueDate is preserved source data, not a universal deadline.

- A comparison with no changes is not proof that no vulnerabilities exist. This tool does not perform background monitoring.


## Catalog metadata changes

```json
[
  {
    "after": "synthetic-after",
    "afterPresent": true,
    "before": "synthetic-before",
    "beforePresent": true,
    "field": "catalogVersion"
  },
  {
    "after": "2099-01-02T12:00:00Z",
    "afterPresent": true,
    "before": "2099-01-01T12:00:00Z",
    "beforePresent": true,
    "field": "dateReleased"
  }
]
```

## Record changes

### CVE-2099-0001 (changed)

```json
{
  "after": {
    "cveID": "CVE-2099-0001",
    "dateAdded": "2099-01-01",
    "dueDate": "2099-02-01",
    "extension": {
      "label": "after"
    },
    "notes": "",
    "product": "Synthetic Product",
    "requiredAction": "Synthetic example only; no real action",
    "shortDescription": "Not a real vulnerability",
    "vendorProject": "Example Vendor",
    "vulnerabilityName": "Synthetic example only"
  },
  "before": {
    "cveID": "CVE-2099-0001",
    "dateAdded": "2099-01-01",
    "dueDate": "2099-01-31",
    "extension": {
      "label": "before"
    },
    "notes": "",
    "product": "Synthetic Product",
    "requiredAction": "Synthetic example only; no real action",
    "shortDescription": "Not a real vulnerability",
    "vendorProject": "Example Vendor",
    "vulnerabilityName": "Synthetic example only"
  },
  "fields": [
    {
      "after": "2099-02-01",
      "afterPresent": true,
      "before": "2099-01-31",
      "beforePresent": true,
      "field": "dueDate"
    },
    {
      "after": {
        "label": "after"
      },
      "afterPresent": true,
      "before": {
        "label": "before"
      },
      "beforePresent": true,
      "field": "extension"
    }
  ]
}
```

### CVE-2099-0002 (removed)

```json
{
  "after": null,
  "before": {
    "cveID": "CVE-2099-0002",
    "dateAdded": "2099-01-01",
    "dueDate": "2099-01-31",
    "extension": {
      "label": "before"
    },
    "notes": "",
    "product": "Synthetic Product",
    "requiredAction": "Synthetic example only; no real action",
    "shortDescription": "Not a real vulnerability",
    "vendorProject": "Example Vendor",
    "vulnerabilityName": "Synthetic example only"
  },
  "fields": []
}
```

### CVE-2099-0003 (added)

```json
{
  "after": {
    "cveID": "CVE-2099-0003",
    "dateAdded": "2099-01-01",
    "dueDate": "2099-01-31",
    "extension": {
      "label": "before"
    },
    "notes": "",
    "product": "Synthetic Product",
    "requiredAction": "Synthetic example only; no real action",
    "shortDescription": "Not a real vulnerability",
    "vendorProject": "Example Vendor",
    "vulnerabilityName": "Synthetic example only"
  },
  "before": null,
  "fields": []
}
```
