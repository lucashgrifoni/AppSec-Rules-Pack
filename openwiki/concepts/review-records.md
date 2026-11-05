---
type: "concept"
title: "Review records and exceptions"
description: "Interpret self-declared rule outcomes, cited evidence and exception dates against the pack policy."
tags: ["review","evidence","exceptions"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T19:35:44.861Z
sources:
  - id: openwiki-source-725c0a0d0a2788b2192aa135
    resource: repo://src/appsec_rules_pack/review.py
generated: { by: "codex", at: "2026-10-14T19:35:44.861Z" }
---

# Review records and exceptions

## A record is checked against a pack

The review path first validates the pack, then validates the record schema and pack identity. Unknown rule IDs and duplicate results are errors. Enabled rules missing from the record become unreviewed outcomes with warnings, rather than silently disappearing ([record checking](../../src/appsec_rules_pack/review.py#L109-L237)). The record's contents remain self-declared evidence; format checks do not independently observe the application.

## Evidence and exception semantics differ

A met result needs at least one evidence entry. Justified statuses without notes produce warnings. An exception block belongs to an excepted result and must be allowed by the rule's policy, include required fields and remain inside the allowed time window ([entry checks](../../src/appsec_rules_pack/review.py#L245-L352)).

Expiry here rejects `expires_at <= as_of`. The grant date comes from granted_at when provided, otherwise the review date; a nonpositive or oversized window is rejected. This boundary differs from tools whose expiry remains valid through the named date, so preserve the contract when exchanging records.

The CI gate consumes the review report and decides whether outcomes such as unreviewed or not-met may proceed. Validation cannot prove an exception was legitimately approved outside the record. See [pack validation](../architecture/pack-validation.md) for structural issues and [derived artifacts](../workflows/derived-artifacts.md) for catalogs.
