---
type: "quickstart"
title: "AppSec rules pack and review records"
description: "Route pack validation, self-declared review records and derived catalogs to their separate contracts."
tags: ["appsec","rules","review"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:35:44.861Z
sources:
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
generated: { by: "codex", at: "2026-10-14T19:35:44.861Z" }
---

# AppSec rules pack and review records

The package installs `appsec-rules` and requires Python3.11 or newer. It validates rule packs and review records; it does not execute the review rules against application code ([package metadata](../pyproject.toml#L5-L10), [entrypoint](../pyproject.toml#L62-L63), [scope](../README.md#scope)).

## Choose a task

| Task | Page |
|---|---|
| Trace YAML loading, schema/semantic checks and CLI outcomes | [Pack validation](architecture/pack-validation.md) |
| Interpret evidence, exceptions and missing review results | [Review records](concepts/review-records.md) |
| Distinguish an index, scaffold and SARIF catalog from detections | [Derived artifacts](workflows/derived-artifacts.md) |
| Maintain the repository wiki | [OpenWiki setup](../docs/openwiki.md) |

The [README](../README.md) contains installation and baseline examples. Framework mappings support a review; they do not establish regulatory conformance or prove a declared evidence item is true. Use the external CI gate's policy to decide which validated outcomes may proceed.
