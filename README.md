# x2StockData

Verifiable data-package mechanisms and one explicitly synthetic example for x2Stock. This repository does not distribute real market history, news, personal data or provider credentials. Tushare access permissions do not establish redistribution rights; real provider data stays local unless separately authorized.

Original tool code uses MIT. The explicitly synthetic example uses [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/legalcode). SHA-256 checks integrity; it does not establish data license or authenticate an arbitrary publisher.

## Usage

Requires Python 3.11+; no external packages.

```text
python tools/package.py verify --root .
python tools/package.py import --root . --destination ./local-packages
python tools/package.py upload-once --root .
```

Import copies a verified package atomically into a separate local directory; it does not implicitly build or migrate a business database. Upload is disabled by default. If explicitly enabled, it only pushes the exact reviewed mechanism tree and synthetic package to MrLaoGe/x2StockData, with normal fast-forward Git behavior and existing Git credential handling. No credentials are read or printed by the tool. Scheduled synchronization skips unchanged commits and uses at least a one-hour interval.

Downloads allow only immutable exact-commit paths under raw.githubusercontent.com/MrLaoGe/x2StockData and reject every redirect before contacting its target. Paths, reparse points, duplicate Windows aliases, schema, original fixture content and size limits are checked. No promise of freely redistributed full history is made.
