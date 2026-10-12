"""Evaluate the firewall against evals/dataset.jsonl.

    python evals/run_evals.py                 # rules-only
    ANTHROPIC_API_KEY=... python evals/run_evals.py   # also runs the hybrid pipeline (real API calls)

Reports accuracy, attack catch rate (recall on label="attack"), and false-positive rate
(genuine messages wrongly blocked), overall and per category, for rules-only and — only when
ANTHROPIC_API_KEY is set and the `anthropic` package is importable — for the hybrid pipeline.
Writes evals/RESULTS.md. Never fabricates hybrid numbers: if no key is present, that section
says so plainly instead of being silently omitted or guessed at.
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bankguard import Config, Firewall  # noqa: E402

DATASET_PATH = ROOT / "evals" / "dataset.jsonl"
RESULTS_PATH = ROOT / "evals" / "RESULTS.md"


def load_dataset() -> list[dict]:
    rows = []
    with open(DATASET_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def run_pipeline(fw: Firewall, rows: list[dict]) -> list[dict]:
    """Returns rows augmented with predicted status, latency, and whether it was a miss."""
    out = []
    for row in rows:
        t0 = time.perf_counter()
        verdict = fw.check(row["text"], source=row.get("source", "user"))
        elapsed = (time.perf_counter() - t0) * 1000
        predicted_blocked = verdict["status"] == "blocked"
        expected_blocked = row["label"] == "attack"
        out.append({
            **row,
            "predicted": "blocked" if predicted_blocked else "safe",
            "correct": predicted_blocked == expected_blocked,
            "risk_score": verdict["risk_score"],
            "latency_ms": elapsed,
        })
    return out


def summarize(results: list[dict], group_key: str | None = None) -> dict:
    def _stats(rs):
        total = len(rs)
        attacks = [r for r in rs if r["label"] == "attack"]
        genuine = [r for r in rs if r["label"] == "genuine"]
        caught = sum(1 for r in attacks if r["predicted"] == "blocked")
        fps = sum(1 for r in genuine if r["predicted"] == "blocked")
        correct = sum(1 for r in rs if r["correct"])
        return {
            "total": total,
            "n_attacks": len(attacks),
            "n_genuine": len(genuine),
            "accuracy": correct / total if total else 0.0,
            "catch_rate": caught / len(attacks) if attacks else None,
            "false_positive_rate": fps / len(genuine) if genuine else None,
            "avg_latency_ms": sum(r["latency_ms"] for r in rs) / total if total else 0.0,
        }

    summary = {"overall": _stats(results)}
    if group_key:
        groups = defaultdict(list)
        for r in results:
            groups[r[group_key]].append(r)
        summary["by_category"] = {k: _stats(v) for k, v in sorted(groups.items())}
    return summary


def misses(results: list[dict]) -> list[dict]:
    return [r for r in results if not r["correct"]]


def fmt_pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def render_table(summary: dict) -> str:
    lines = [
        "| Category | N | Accuracy | Catch rate | False-positive rate | Avg latency |",
        "|---|---|---|---|---|---|",
    ]
    o = summary["overall"]
    lines.append(f"| **overall** | {o['total']} | {fmt_pct(o['accuracy'])} | "
                  f"{fmt_pct(o['catch_rate'])} | {fmt_pct(o['false_positive_rate'])} | "
                  f"{o['avg_latency_ms']:.2f} ms |")
    for cat, s in summary["by_category"].items():
        lines.append(f"| {cat} | {s['total']} | {fmt_pct(s['accuracy'])} | "
                      f"{fmt_pct(s['catch_rate'])} | {fmt_pct(s['false_positive_rate'])} | "
                      f"{s['avg_latency_ms']:.2f} ms |")
    return "\n".join(lines)


def render_misses(miss_rows: list[dict], label: str) -> str:
    if not miss_rows:
        return f"No misses for {label}.\n"
    lines = [f"{len(miss_rows)} miss(es) for {label}:\n"]
    for r in miss_rows:
        want = "blocked" if r["label"] == "attack" else "safe"
        lines.append(f"- `{r['id']}` [{r['category']}{', ' + r['variant'] if 'variant' in r else ''}] "
                      f"expected **{want}**, got **{r['predicted']}** (risk={r['risk_score']}) "
                      f"— {r['text'][:90]!r}")
    return "\n".join(lines) + "\n"


def try_build_hybrid_firewall():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None, "ANTHROPIC_API_KEY not set"
    try:
        from bankguard.llm_judge import ClaudeJudge
        judge = ClaudeJudge()
    except Exception as exc:
        return None, f"judge unavailable: {exc!r}"
    return Firewall(Config(), judge=judge), None


def main():
    rows = load_dataset()
    print(f"Loaded {len(rows)} rows from {DATASET_PATH.relative_to(ROOT)}")

    rules_fw = Firewall()
    rules_results = run_pipeline(rules_fw, rows)
    rules_summary = summarize(rules_results, "category")
    rules_misses = misses(rules_results)

    hybrid_fw, hybrid_skip_reason = try_build_hybrid_firewall()
    hybrid_results = hybrid_summary = hybrid_misses_list = None
    if hybrid_fw is not None:
        print("ANTHROPIC_API_KEY present — running hybrid pipeline (real API calls)...")
        hybrid_results = run_pipeline(hybrid_fw, rows)
        hybrid_summary = summarize(hybrid_results, "category")
        hybrid_misses_list = misses(hybrid_results)
    else:
        print(f"Skipping hybrid pipeline: {hybrid_skip_reason}")

    md = []
    md.append("# BankGuard eval results\n")
    md.append(f"Dataset: `{DATASET_PATH.relative_to(ROOT)}` — {len(rows)} labelled messages "
               f"({sum(1 for r in rows if r['label'] == 'attack')} attack, "
               f"{sum(1 for r in rows if r['label'] == 'genuine')} genuine).\n")
    md.append("Generated by `evals/run_evals.py`. Numbers below are from an actual run against "
               "the current rule engine (and the hybrid pipeline when a key is present) — not "
               "hand-estimated.\n")

    md.append("## Rules-only pipeline\n")
    md.append(render_table(rules_summary))
    md.append("")
    md.append("### Misses (rules-only)\n")
    md.append(render_misses(rules_misses, "rules-only"))

    md.append("## Hybrid pipeline (rules + LLM judge)\n")
    if hybrid_summary is not None:
        md.append(render_table(hybrid_summary))
        md.append("")
        md.append("### Misses (hybrid)\n")
        md.append(render_misses(hybrid_misses_list, "hybrid"))
    else:
        md.append(f"**Not run in this report: {hybrid_skip_reason}.** Set `ANTHROPIC_API_KEY` "
                   "(and `pip install anthropic`) and re-run `python evals/run_evals.py` to "
                   "populate this section with real hybrid numbers. This report does not "
                   "fabricate hybrid results in its absence.\n")

    md.append("## Honest limitations\n")
    md.append(
        "- This dataset was written by the same people who wrote the rules, so it is not a "
        "blind test — some attack phrasings closely track rule patterns (e.g. "
        "`instruction_override`'s \"ignore ... instructions\" wording) and will over-state "
        "real-world catch rate. The multilingual and obfuscated categories are a better proxy "
        "for genuine generalization since they paraphrase rather than reuse vocabulary.\n"
        "- `genuine_trigger_words` is the highest-signal category for false positives: it "
        "specifically probes words (\"ignore\", \"secret\", \"urgent\", \"override\") that the "
        "rule engine keys on, used in ordinary banking sentences.\n"
        "- 184 rows is enough to catch gross regressions, not to produce statistically tight "
        "confidence intervals per category (some categories have as few as 10 rows).\n"
    )

    RESULTS_PATH.write_text("\n".join(md), encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH.relative_to(ROOT)}")
    print("\n--- rules-only summary ---")
    print(render_table(rules_summary))
    if hybrid_summary is not None:
        print("\n--- hybrid summary ---")
        print(render_table(hybrid_summary))


if __name__ == "__main__":
    main()
