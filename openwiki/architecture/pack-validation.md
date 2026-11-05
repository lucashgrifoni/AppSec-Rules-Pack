---
type: "architecture"
title: "Pack loading and validation"
description: "Trace bounded YAML loading into stable schema/semantic issues and CLI pass/fail behavior."
tags: ["validation","yaml","schema"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:35:44.861Z
sources:
  - id: openwiki-source-b0bd423f931b969adbed744f
    resource: repo://src/appsec_rules_pack/cli.py
  - id: openwiki-source-12b6608aacae002ff2be1863
    resource: repo://src/appsec_rules_pack/loader.py
  - id: openwiki-source-712c00a2c928e73a1e2e3224
    resource: repo://src/appsec_rules_pack/validator.py
generated: { by: "codex", at: "2026-10-14T19:35:44.861Z" }
---

# Pack loading and validation

## Loader owns representation safety

The specialized SafeLoader rejects YAML aliases and duplicate mapping keys. It limits file size before parsing and normalizes invalid unquoted dates into YAML errors rather than leaking a parser exception. The configured size bound is10MiB ([loader](../../src/appsec_rules_pack/loader.py#L1-L53)). This is input handling for rule packs, not a general-purpose secret scanner.

## Validator owns issues

`validate_rules_payload` combines packaged-schema checks with semantic checks, returning rule count and typed issues. The semantic path covers duplicate IDs, exception consistency, mapping formats, deprecation, schema version and sensitive-value patterns; requiring examples is opt-in ([validation entry](../../src/appsec_rules_pack/validator.py#L264-L275), [semantic checks](../../src/appsec_rules_pack/validator.py#L479-L494)). File validation attaches source line/column positions when available. Multi-file validation also accounts for IDs duplicated across files.

## CLI owns strictness and output

The CLI summarizes errors/warnings. Normal validation fails for errors; `--fail-on-warnings` also rejects a warning-only result. It can emit a structured report and exits1 on failed validation ([CLI decision](../../src/appsec_rules_pack/cli.py#L379-L409)). A derived report or export is a separate operation and should not be read as proof that validation was run first.

Return to [quickstart](../quickstart.md) or continue with [review records](../concepts/review-records.md).
