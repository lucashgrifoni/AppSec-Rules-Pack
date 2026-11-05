---
type: "workflow"
title: "Indexes, scaffolds and SARIF catalogs"
description: "Separate derived rule metadata from executable detections and application scan findings."
tags: ["exports","semgrep","sarif"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:35:44.861Z
sources:
  - id: openwiki-source-b0bd423f931b969adbed744f
    resource: repo://src/appsec_rules_pack/cli.py
  - id: openwiki-source-e94b9779e47958dffc67154d
    resource: repo://src/appsec_rules_pack/sarif_export.py
  - id: openwiki-source-4d633f70ecede30abc3aac0d
    resource: repo://src/appsec_rules_pack/semgrep_scaffold.py
generated: { by: "codex", at: "2026-10-14T19:35:44.861Z" }
---

# Indexes, scaffolds and SARIF catalogs

## Exports derive metadata

The CLI's index, Semgrep and SARIF export commands load pack payloads and invoke their respective builders. Derivation is distinct from structural/semantic validation ([CLI exports](../../src/appsec_rules_pack/cli.py#L413-L495)). Run the requested validation policy before relying on a derived artifact.

## The Semgrep scaffold needs real detection logic

The scaffold maps rule metadata and severity into Semgrep-shaped output, emits only enabled rules and assigns a placeholder detection pattern. It is expressly non-runnable until a consumer replaces that placeholder with a real detection ([scaffold builder](../../src/appsec_rules_pack/semgrep_scaffold.py)). The README separately documents optional executable Semgrep rules; those are a different surface from exporting this metadata scaffold.

## SARIF here is a rule catalog

The SARIF builder includes enabled rule descriptors in the tool's catalog and writes an empty results array. It does not report a scan that found zero vulnerabilities ([SARIF builder](../../src/appsec_rules_pack/sarif_export.py#L74-L104)). Keep that distinction when importing the output into another system.

Use the existing export examples and regression tests for a consumer integration. Return to [quickstart](../quickstart.md) for routing.
