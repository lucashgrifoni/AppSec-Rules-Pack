"""Property-based coverage of `review`: a malformed record is an issue, never a crash."""

from __future__ import annotations

import copy
import datetime as dt
import re
from pathlib import Path
from typing import Any

import yaml
from hypothesis import given
from hypothesis import strategies as st

from appsec_rules_pack.review import review_payloads

ROOT = Path(__file__).resolve().parents[2]
BASELINE = yaml.safe_load((ROOT / "rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
RECORD = yaml.safe_load(
    (ROOT / "examples/review/payments-api-review.yaml").read_text(encoding="utf-8")
)
DOCUMENTED_CODES = frozenset(
    re.findall(r"^\| `([a-z0-9-]+)` \|", (ROOT / "VERSIONING.md").read_text("utf-8"), re.M)
)
STATUSES = ("met", "not-met", "not-applicable", "excepted")

dates = st.dates(min_value=dt.date(1990, 1, 1), max_value=dt.date(2100, 12, 31))
date_like = st.one_of(dates, dates.map(dt.date.isoformat), st.text(max_size=12))
leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=30), date_like)


@st.composite
def mutated_records(draw) -> Any:
    record = copy.deepcopy(RECORD)
    results = record["results"]
    for _ in range(draw(st.integers(min_value=1, max_value=4))):
        entry = draw(st.sampled_from(results)) if results else None
        action = draw(
            st.sampled_from(
                ["status", "drop", "duplicate", "exception", "evidence", "field", "rule"]
            )
        )
        if entry is None or action == "drop":
            if results:
                results.pop(draw(st.integers(min_value=0, max_value=len(results) - 1)))
        elif action == "status":
            entry["status"] = draw(st.one_of(st.sampled_from(STATUSES), leaf))
        elif action == "duplicate":
            results.append(copy.deepcopy(entry))
        elif action == "exception":
            entry["exception"] = draw(
                st.one_of(
                    leaf,
                    st.fixed_dictionaries(
                        {"expires_at": date_like},
                        optional={
                            "granted_at": date_like,
                            "owner": leaf,
                            "justification": leaf,
                            "compensating_control": leaf,
                            "validation_plan": leaf,
                        },
                    ),
                )
            )
        elif action == "evidence":
            entry["evidence"] = draw(st.one_of(leaf, st.lists(leaf, max_size=3)))
        elif action == "field":
            record["review"][draw(st.sampled_from(["pack", "date", "subject", "x"]))] = draw(leaf)
        else:
            entry["rule"] = draw(
                st.one_of(st.sampled_from([r["id"] for r in BASELINE["rules"]]), leaf)
            )
    return record


@given(mutated_records(), dates)
def test_review_of_any_record_returns_documented_issues(record: Any, as_of: dt.date) -> None:
    result = review_payloads(BASELINE, record, as_of=as_of)

    assert all(issue.code in DOCUMENTED_CODES for issue in result.issues)
    assert result.ok == (result.error_count == 0)
    assert len({outcome.rule_id for outcome in result.outcomes}) == len(result.outcomes)
    if result.outcomes:
        enabled = {r["id"] for r in BASELINE["rules"] if r["status"] == "enabled"}
        assert enabled <= {outcome.rule_id for outcome in result.outcomes}
