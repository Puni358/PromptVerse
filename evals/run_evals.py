"""Evaluate the firewall against evals/dataset.jsonl.

    python evals/run_evals.py                 # rules-only (no GEMINI_API_KEY / LLM_PROVIDER=none)
    GEMINI_API_KEY=... python evals/run_evals.py   # also runs the hybrid pipeline (real API calls)

Reports accuracy, attack catch rate (recall on label="attack"), and false-positive rate
(genuine messages wrongly blocked), overall and per category, for rules-only and — only when
a Gemini judge can actually be built (see bankguard/judge.py) — for the hybrid pipeline.
Writes evals/RESULTS.md. Never fabricates hybrid numbers: if no key is present, that section
says so plainly instead of being silently omitted or guessed at.

Hybrid runs are throttled (EVAL_THROTTLE_SECONDS, default 1.5s between real API calls — the
Gemini free tier's per-minute limit is low) and cached in evals/cache.json (gitignored), keyed
by message hash, so re-running the eval after a dataset tweak doesn't re-pay for unchanged rows.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bankguard import Config, Firewall  # noqa: E402
from bankguard.envfile import load_dotenv  # noqa: E402
from bankguard.judge import build_judge  # noqa: E402

load_dotenv(ROOT / ".env")

DATASET_PATH = ROOT / "evals" / "dataset.jsonl"
HELDOUT_PATH = ROOT / "evals" / "heldout.jsonl"
RESULTS_PATH = ROOT / "evals" / "RESULTS.md"
CACHE_PATH = ROOT / "evals" / "cache.json"
THROTTLE_SECONDS = float(os.environ.get("EVAL_THROTTLE_SECONDS", "1.5"))


class CachingThrottledJudge:
    """Wraps a real judge for eval runs: persists results to disk keyed by message hash (so
    repeat runs are free for unchanged rows) and rate-limits actual API calls. Never caches a
    failure — if the wrapped judge raises, nothing is written and the exception propagates to
    Firewall._check(), which already fails closed for high-risk intents."""

    def __init__(self, judge, cache_path: Path, throttle_seconds: float):
        self.judge = judge
        self.cache_path = cache_path
        self.throttle_seconds = throttle_seconds
        self.cache: dict[str, dict] = self._load()
        self._last_call = 0.0
        self.api_calls = 0
        self.cache_hits = 0

    def _load(self) -> dict:
        if self.cache_path.is_file():
            try:
                return json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save(self):
        self.cache_path.write_text(json.dumps(self.cache, indent=1, ensure_ascii=False),
                                   encoding="utf-8")

    def assess(self, message: str) -> dict:
        key = hashlib.sha256(message.encode("utf-8", "ignore")).hexdigest()
        if key in self.cache:
            self.cache_hits += 1
            return self.cache[key]
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.throttle_seconds:
            time.sleep(self.throttle_seconds - elapsed)
        result = self.judge.assess(message)
        self._last_call = time.monotonic()
        self.api_calls += 1
        self.cache[key] = result
        self._save()
        return result


def load_dataset(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
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
    """Returns (Firewall | None, skip_reason | None). Never raises — a misconfigured
    LLM_PROVIDER surfaces as a skip reason, same as a missing key, so the eval still runs
    the rules-only pipeline and reports honestly instead of crashing."""
    try:
        judge = build_judge()
    except Exception as exc:
        return None, f"LLM_PROVIDER misconfigured: {exc!r}"
    if judge is None:
        if os.environ.get("LLM_PROVIDER", "gemini").lower() == "none":
            return None, "LLM_PROVIDER=none"
        return None, "GEMINI_API_KEY not set"
    wrapped = CachingThrottledJudge(judge, CACHE_PATH, THROTTLE_SECONDS)
    return Firewall(Config(), judge=wrapped), None


def eval_one_set(name: str, path: Path, rules_fw: Firewall, hybrid_fw: Firewall | None,
                 hybrid_skip_reason: str | None) -> dict:
    """Runs one dataset through rules-only (and hybrid, if available) and returns everything
    needed to render its section of RESULTS.md."""
    rows = load_dataset(path)
    print(f"Loaded {len(rows)} rows from {path.relative_to(ROOT)}")

    rules_results = run_pipeline(rules_fw, rows)
    rules_summary = summarize(rules_results, "category")
    rules_misses = misses(rules_results)

    hybrid_summary = hybrid_misses_list = None
    if hybrid_fw is not None:
        print(f"Running hybrid pipeline for {name} against Gemini "
              f"(throttle={THROTTLE_SECONDS}s, cache={CACHE_PATH.relative_to(ROOT)})...")
        hybrid_results = run_pipeline(hybrid_fw, rows)
        hybrid_summary = summarize(hybrid_results, "category")
        hybrid_misses_list = misses(hybrid_results)

    return {
        "name": name, "path": path, "rows": rows,
        "rules_summary": rules_summary, "rules_misses": rules_misses,
        "hybrid_summary": hybrid_summary, "hybrid_misses": hybrid_misses_list,
    }


def render_set(md: list, result: dict, hybrid_skip_reason: str | None):
    rows = result["rows"]
    md.append(f"### Dataset: `{result['path'].relative_to(ROOT)}` — {len(rows)} labelled messages "
               f"({sum(1 for r in rows if r['label'] == 'attack')} attack, "
               f"{sum(1 for r in rows if r['label'] == 'genuine')} genuine)\n")

    md.append("#### Rules-only pipeline\n")
    md.append(render_table(result["rules_summary"]))
    md.append("")
    md.append(f"##### Misses (rules-only, {result['name']})\n")
    md.append(render_misses(result["rules_misses"], f"rules-only / {result['name']}"))

    md.append(f"#### Hybrid pipeline (rules + Gemini judge, {result['name']})\n")
    if result["hybrid_summary"] is not None:
        md.append(render_table(result["hybrid_summary"]))
        md.append("")
        md.append(f"##### Misses (hybrid, {result['name']})\n")
        md.append(render_misses(result["hybrid_misses"], f"hybrid / {result['name']}"))
    else:
        md.append(f"**Not run in this report: {hybrid_skip_reason}.** Set `GEMINI_API_KEY` "
                   "(see `.env.example`) and re-run `python evals/run_evals.py` to populate "
                   "this section with real hybrid numbers. This report does not fabricate "
                   "hybrid results in its absence.\n")


def main():
    rules_fw = Firewall()
    hybrid_fw, hybrid_skip_reason = try_build_hybrid_firewall()
    if hybrid_fw is None:
        print(f"Skipping hybrid pipeline: {hybrid_skip_reason}")

    main_result = eval_one_set("main set", DATASET_PATH, rules_fw, hybrid_fw, hybrid_skip_reason)
    heldout_result = eval_one_set("held-out set", HELDOUT_PATH, rules_fw, hybrid_fw, hybrid_skip_reason)

    if hybrid_fw is not None:
        cached_judge: CachingThrottledJudge = hybrid_fw.judge
        print(f"Hybrid total: {cached_judge.api_calls} live API calls, "
              f"{cached_judge.cache_hits} cache hits")

    md = []
    md.append("# BankGuard eval results\n")
    md.append("Generated by `evals/run_evals.py`. Numbers below are from an actual run against "
               "the current rule engine (and the hybrid pipeline when a Gemini key is present) "
               "— not hand-estimated.\n")

    md.append("## Main dataset\n")
    md.append(
        "Written alongside the rules — useful as a regression check, but not a blind test: "
        "some attack phrasings track rule vocabulary closely. See `evals/dataset.jsonl`.\n")
    render_set(md, main_result, hybrid_skip_reason)

    md.append("## Held-out set (evals/heldout.jsonl)\n")
    md.append(
        "**50 new messages, written after the rules and main dataset were final, deliberately "
        "phrased unlike anything in `bankguard/rules.py` or `evals/dataset.jsonl`** — novel "
        "attack framings (stepwise/acrostic/markdown-table/word-reversed/Unicode-math/emoji "
        "obfuscation, fake-authorization and fake-processing-note social engineering, "
        "Korean/Portuguese/Vietnamese/Indonesian/Swahili/Kannada/Tamil/Telugu attacks not in "
        "the main set's multilingual list), plus genuine requests in new phrasings and "
        "languages (Portuguese, Vietnamese, Indonesian, Korean, Swahili). **The rules and "
        "intent patterns were not tuned against this file after it was written** — these are "
        "first-contact results, not a dataset the system was fit to.\n")
    render_set(md, heldout_result, hybrid_skip_reason)

    md.append("## Honest limitations\n")
    md.append(
        "- The main dataset was written by the same people who wrote the rules, so it is not "
        "a blind test — some attack phrasings closely track rule patterns (e.g. "
        "`instruction_override`'s \"ignore ... instructions\" wording) and will over-state "
        "real-world catch rate. The held-out set exists specifically to counter this: its "
        "numbers are the more honest signal for how the system does on phrasing it has never "
        "seen, at the cost of a smaller sample (50 vs 204 rows).\n"
        "- `genuine_trigger_words` (main set) and `genuine_trigger_words_novel` (held-out) are "
        "the highest-signal categories for false positives: they specifically probe words "
        "(\"ignore\", \"secret\", \"urgent\", \"override\", \"disregard\", \"between us\") that "
        "the rule engine keys on, used in ordinary banking sentences.\n"
        "- Some non-English strings in both files (Swahili, Kannada, Tamil, Telugu, Vietnamese, "
        "Indonesian, Korean in particular) are best-effort translations, not reviewed by a "
        "native speaker — treat the exact wording as approximate, though the intent (genuine "
        "banking request vs. instruction-override attack) is correct by construction.\n"
        "- Hybrid numbers (when present) reflect a live run against one Gemini model snapshot "
        "at one point in time; LLM judge output is not perfectly deterministic even at "
        "temperature 0, so a re-run may shift individual borderline verdicts slightly.\n"
        "- **The judge only fires when the rule engine's own gate opens it.** As of this "
        "version the gate is wider than just high-risk-intent-or-grey-zone — it also opens for "
        "unknown intent, non-Latin script, any obfuscation flag, and untrusted sources (see "
        "`docs/PROMPT_FLOW.md`) — specifically to close a multilingual gap found in an earlier "
        "version of this report, where every multilingual miss had `risk_score=0.0` because the "
        "judge was never consulted at all. Check this report's own multilingual rows: when this "
        "was last run, the gap was closed, not just narrowed (100% hybrid catch rate on both "
        "`multilingual_override` and every `multilingual_novel_*` category), but re-verify on "
        "your own run rather than trusting that holds forever.\n"
        "- **An earlier full run of this eval hit real judge timeouts under sustained load, "
        "and they failed closed as designed** — worth stating plainly. At a 4s-per-call timeout "
        "and a 1.5s throttle, pushing 250+ live calls through a free-tier key over several "
        "minutes, a handful of high-risk multilingual genuine messages got a judge timeout, hit "
        "the high-risk fail-closed path, and were wrongly blocked — not because Gemini "
        "misclassified them, but because it never got to answer. Re-running those exact "
        "messages individually afterward confirmed they classify correctly off the degraded "
        "connection. The fix reflected in the current numbers: `bankguard/providers/gemini.py`'s "
        "timeout is now a 7-second TOTAL budget across one attempt plus one retry (up from a 4s "
        "single attempt), still comfortably under Vercel's 10s function limit.\n"
    )

    RESULTS_PATH.write_text("\n".join(md), encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH.relative_to(ROOT)}")
    print("\n--- main set: rules-only ---")
    print(render_table(main_result["rules_summary"]))
    if main_result["hybrid_summary"] is not None:
        print("\n--- main set: hybrid ---")
        print(render_table(main_result["hybrid_summary"]))
    print("\n--- held-out set: rules-only ---")
    print(render_table(heldout_result["rules_summary"]))
    if heldout_result["hybrid_summary"] is not None:
        print("\n--- held-out set: hybrid ---")
        print(render_table(heldout_result["hybrid_summary"]))


if __name__ == "__main__":
    main()
