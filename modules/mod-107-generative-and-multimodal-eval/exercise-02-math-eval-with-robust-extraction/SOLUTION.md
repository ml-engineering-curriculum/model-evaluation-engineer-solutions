# exercise-02 — Math Eval with Robust Extraction — Solution

## 1. Solution overview

A math eval has two failure modes that look identical in a confusion matrix but are completely different bugs:

- The model **solved the problem** but the extractor pulled the wrong span out of a long chain of thought — a *measurement* bug.
- The model **did not solve the problem** but happened to emit the gold token somewhere in its reasoning — a *leakage* bug.

Both show up as "ambiguous" results in a naive exact-match pipeline. The exercise asks the learner to build a math eval whose extraction and equivalence steps are **explicit, auditable, and tested**, so the headline number is a defensible measurement rather than an artifact of the regex that scraped the answer.

The reference answer has four deliverables:

1. A **problem schema and dataset layout** that keeps the model-visible problem, the gold *canonical* answer, and the acceptable *alternate forms* separated in the JSON row.
2. An **extraction + normalization + equivalence pipeline** — a layered `boxed` → `the answer is` → `last-expression` extractor, a normalizer that strips LaTeX cosmetics, and a symbolic equivalence step (SymPy for math; a committed numeric tolerance for floats).
3. A **grader** that returns a *trace* per item (which extractor fired, what was extracted, what was normalized, which equivalence path matched) and a `verdict` of `correct` / `wrong` / `no_answer` / `extraction_failed`.
4. A **review checklist** that treats `extraction_failed` and `no_answer` as first-class outcomes, not silent zeros. A math eval whose "accuracy" rolls a 7% extraction-failure rate into the wrong column is lying by about 7%.

This maps to the NIST AI RMF `MEASURE` function, which requires measurements to be "tested, documented, and tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — an extractor that is a 40-line regex nobody tests fails that bar immediately. The adversarial lens is OWASP ML Top 10 **ML08 Model Skewing** — a loose equivalence check (e.g., substring match) is a skew in the measurement instrument that silently rewards models for emitting gold tokens anywhere in their output ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS `Craft Adversarial Data` is the technique that exploits exactly such a skew — once an attacker learns the extractor's rules, they can nudge a model's reasoning to game them ([MITRE ATLAS](https://atlas.mitre.org/)).

## 2. Worked implementation

### 2.1 Directory layout

```
math_eval/
  README.md
  problems/
    mini_math_v1.jsonl           # 25 problems, committed
    checksums.sha256
  grader/
    __init__.py
    extract.py                   # layered extractors
    normalize.py                 # LaTeX / unicode / whitespace normalization
    equivalence.py               # SymPy equivalence + numeric tolerance
    grade.py                     # orchestration, returns a Verdict trace
  reproduction/
    run_2026-11-20.yaml
  tests/
    test_extract.py
    test_normalize.py
    test_equivalence.py
    test_grade.py
```

### 2.2 Problem schema

Each row is one JSON object. The gold has two first-class fields: a **canonical** answer (the one the writer committed to) and an **alternates** list (semantically equivalent forms). The grader has to pass canonical *or* any alternate.

```json
{
  "id": "mm-00012",
  "problem": "Simplify $\\frac{2\\sqrt{8}}{\\sqrt{2}}$.",
  "gold": {
    "canonical": "4",
    "alternates": ["4.0", "2^2", "\\frac{4}{1}"],
    "type": "number"
  },
  "topic": "algebra",
  "difficulty": 2,
  "license": "cc-by-4.0",
  "provenance": "authored for exercise-02; not from MATH/GSM8K",
  "notes": "Gold is 4 exactly. Equivalence is numeric for 'number' type."
}
```

Four invariants to enforce in CI (section 3):

- `gold.type` is one of `number`, `expression`, `set`, `interval`, `tuple`, or `string`. Each type has a fixed equivalence function (section 2.5). An unknown type blocks CI; silently defaulting to `string` is how a math eval becomes a substring eval.
- `canonical` must survive the normalizer round-trip (`normalize(canonical) == normalize(canonical)` after the SymPy parser).
- Every string in `alternates` must be equivalent to `canonical` under the type's equivalence function. A broken alternate is a self-check CI finds before any model sees the eval.
- `provenance` and `license` are per-problem. Pulling items from a mixed-license corpus without tagging fails distribution review the first time the eval is published.

### 2.3 Extraction

The extractor is a small chain. The first match wins; each extractor emits a `(span, extractor_name)` pair so the trace tells you exactly which rule fired.

```python
"""Layered extractors for math model outputs.

Order matters: `boxed` is the strongest signal; `the_answer_is` catches
the Minerva-style tail; `final_line` is the last-resort fallback."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Extraction:
    span: str
    extractor: str          # "boxed" | "the_answer_is" | "final_line" | "none"


# \boxed{...} with brace balancing (nested \frac{a}{b} inside boxed is common).
_BOXED_RE = re.compile(r"\\boxed\s*\{")


def _extract_boxed(text: str) -> str | None:
    # Find the LAST \boxed{...} in the text; a correct model often reasons
    # and then writes a final \boxed{...}.
    last = None
    for m in _BOXED_RE.finditer(text):
        start = m.end()  # position just after '{'
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    last = text[start:i]
                    break
            i += 1
    return last


_ANS_PHRASES = [
    r"[Tt]he answer is[:\s]*",
    r"[Aa]nswer[:\s]*",
    r"[Ff]inal answer[:\s]*",
]
_ANS_RE = re.compile(
    r"(?:" + "|".join(_ANS_PHRASES) + r")(?P<ans>.+?)(?:\.|\n|$)"
)


def _extract_the_answer_is(text: str) -> str | None:
    # Take the LAST match; models often restate an intermediate answer.
    last = None
    for m in _ANS_RE.finditer(text):
        last = m.group("ans").strip().strip("$").strip()
    return last


def _extract_final_line(text: str) -> str | None:
    # Last non-empty line, stripped of LaTeX delimiters.
    for line in reversed(text.strip().splitlines()):
        s = line.strip()
        if not s:
            continue
        s = s.strip("$").strip()
        if s:
            return s
    return None


def extract(text: str) -> Extraction:
    if text is None:
        return Extraction("", "none")
    boxed = _extract_boxed(text)
    if boxed is not None:
        return Extraction(boxed.strip(), "boxed")
    tai = _extract_the_answer_is(text)
    if tai is not None:
        return Extraction(tai.strip(), "the_answer_is")
    final = _extract_final_line(text)
    if final is not None:
        return Extraction(final.strip(), "final_line")
    return Extraction("", "none")
```

Properties the extractor must satisfy (`test_extract.py`):

- A response containing `"...so the answer is $x=5$ and \\boxed{5}."` extracts `"5"` via `boxed`, *not* via `the_answer_is`. Boxed wins so the chain is order-stable.
- A response containing `"The answer is 42."` extracts `"42"`.
- A response containing `"Answer: \\frac{3}{4}"` extracts `"\\frac{3}{4}"`.
- A response with only `"...finally, 7"` extracts `"7"` via `final_line`.
- A `\boxed{\\frac{a}{b}}` is extracted as `"\\frac{a}{b}"` (brace balancing works).
- An empty / whitespace-only response returns `Extraction("", "none")` — it does not crash and it does not fall through to some inner regex catch.

### 2.4 Normalization

Normalization is for the *parser*, not the *reader*. The goal is: a string that would read the same to a human maps to the same string pre-SymPy. Everything that is cosmetic goes. Everything that could change semantics stays.

```python
"""Normalization for math expressions before SymPy parsing.

Rules:
  - Unicode minus / minus-sign variants -> ASCII '-'
  - Remove display-math delimiters $, \\(, \\), \\[, \\]
  - Remove '\\left', '\\right' (cosmetic brace pairs in LaTeX)
  - Convert '\\dfrac'/'\\tfrac' to '\\frac'
  - Strip trailing/leading whitespace and surrounding parentheses added for display
  - Collapse multiple spaces
Rules we DO NOT apply:
  - Lowercasing: case-sensitive for variable names
  - Fraction simplification: let SymPy decide equivalence, not the normalizer
  - Numeric rounding: the equivalence step tolerates float error, not the normalizer"""

from __future__ import annotations

import re

_UNICODE_MINUS = dict.fromkeys(["−", "–", "—", "‐"], "-")
_UNICODE_TIMES = {"×": "*", "⋅": "*"}
_UNICODE_DIV   = {"÷": "/"}
_REPL = {**_UNICODE_MINUS, **_UNICODE_TIMES, **_UNICODE_DIV}

_LATEX_COSMETICS = [
    r"\\left", r"\\right",
    r"\$\$", r"\$",
    r"\\\(", r"\\\)", r"\\\[", r"\\\]",
    r"\\displaystyle", r"\\textstyle",
]


def normalize(expr: str) -> str:
    s = expr
    for u, a in _REPL.items():
        s = s.replace(u, a)
    for pat in _LATEX_COSMETICS:
        s = re.sub(pat, "", s)
    s = s.replace("\\dfrac", "\\frac").replace("\\tfrac", "\\frac")
    s = re.sub(r"\s+", " ", s).strip()
    # Trim one surrounding paren pair if the expression is wrapped.
    if s.startswith("(") and s.endswith(")") and _balanced_outer(s):
        s = s[1:-1].strip()
    return s


def _balanced_outer(s: str) -> bool:
    depth = 0
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i != len(s) - 1:
                return False
    return depth == 0
```

### 2.5 Equivalence

Equivalence is **per gold.type**. Each type gets a single function. Never fall through to a substring match.

```python
"""Equivalence checks, dispatched by gold.type."""

from __future__ import annotations

from fractions import Fraction
from typing import Callable

try:
    import sympy
    from sympy.parsing.latex import parse_latex
except ImportError as e:
    raise RuntimeError("SymPy is required for math_eval.equivalence") from e


FLOAT_TOL = 1e-6


def _parse(expr: str):
    # Try LaTeX first (handles \frac, \sqrt, etc.); fall back to SymPy's
    # own parser for simple expressions.
    try:
        return parse_latex(expr)
    except Exception:
        return sympy.sympify(expr, convert_xor=True)


def eq_number(pred: str, gold: str) -> bool:
    try:
        a = float(Fraction(pred.replace(" ", "")))  # exact if possible
    except (ValueError, ZeroDivisionError):
        try:
            a = float(_parse(pred))
        except Exception:
            return False
    try:
        b = float(Fraction(gold.replace(" ", "")))
    except (ValueError, ZeroDivisionError):
        try:
            b = float(_parse(gold))
        except Exception:
            return False
    return abs(a - b) <= FLOAT_TOL * max(1.0, abs(a), abs(b))


def eq_expression(pred: str, gold: str) -> bool:
    try:
        diff = sympy.simplify(_parse(pred) - _parse(gold))
    except Exception:
        return False
    return diff == 0


def eq_set(pred: str, gold: str) -> bool:
    # Parse as a Python-style set literal: "{1, 2, 3}" or "{1,2,3}".
    def _as_set(s: str) -> set:
        s = s.strip().lstrip("{").rstrip("}")
        return {t.strip() for t in s.split(",") if t.strip()}
    return _as_set(pred) == _as_set(gold)


def eq_interval(pred: str, gold: str) -> bool:
    # Equal iff endpoints and inclusivity match; delegate to SymPy.
    try:
        return sympy.Interval(*_endpoints(pred)) == sympy.Interval(*_endpoints(gold))
    except Exception:
        return False


def _endpoints(s: str):
    # Parse "(a, b]" / "[a, b)" / "(a, b)" / "[a, b]"
    s = s.strip()
    left_open = s[0] == "("
    right_open = s[-1] == ")"
    lo, hi = s[1:-1].split(",")
    return (sympy.sympify(lo), sympy.sympify(hi), left_open, right_open)


def eq_tuple(pred: str, gold: str) -> bool:
    def _as_tuple(s: str) -> tuple:
        s = s.strip().lstrip("(").rstrip(")")
        return tuple(t.strip() for t in s.split(","))
    return _as_tuple(pred) == _as_tuple(gold)


def eq_string(pred: str, gold: str) -> bool:
    # Exact string match after normalization. Use only for problem types
    # whose answer is a word (e.g., "even", "yes", "no").
    return pred == gold


DISPATCH: dict[str, Callable[[str, str], bool]] = {
    "number":     eq_number,
    "expression": eq_expression,
    "set":        eq_set,
    "interval":   eq_interval,
    "tuple":      eq_tuple,
    "string":     eq_string,
}


def equivalent(pred: str, gold: str, gold_type: str) -> bool:
    try:
        fn = DISPATCH[gold_type]
    except KeyError:
        raise ValueError(f"unknown gold.type: {gold_type}") from None
    return fn(pred, gold)
```

Three rules worth internalizing:

- **No fallback to substring.** `equivalent` either matches under the type-specific check or returns `False`. A fallback "...otherwise check if gold is in pred" turns the grader into a leakage detector that congratulates any model that mentions `"4"` anywhere while explaining why the answer is `8`.
- **Float tolerance is relative, not absolute.** `1e-6 * max(1, |a|, |b|)` tolerates rounding on big numbers without pretending `1e-5 == 0`.
- **Integer answers are parsed exactly.** `Fraction("0.1") != Fraction(1, 10)` — `Fraction` of a string reads the decimal literally. `Fraction("1/2")` is exact. The grader tries exact first, then falls back to `_parse` (SymPy) for non-rational answers.

### 2.6 Grader

The grader returns a `Verdict` dataclass whose instance *is* the audit trail for one item. `verdict` is one of a fixed set of values; there is no "partial credit" column.

```python
"""Orchestrate extract -> normalize -> equivalence and emit a Verdict trace."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .extract import extract
from .normalize import normalize
from .equivalence import equivalent, DISPATCH


VerdictLabel = Literal["correct", "wrong", "no_answer", "extraction_failed"]


@dataclass
class Verdict:
    item_id: str
    label: VerdictLabel
    extractor: str
    raw_span: str
    normalized_pred: str
    matched_alternate: str | None = None
    notes: list[str] = field(default_factory=list)


def grade_one(item: dict, model_output: str) -> Verdict:
    gold_type = item["gold"]["type"]
    if gold_type not in DISPATCH:
        raise ValueError(f"item {item['id']}: unknown gold.type {gold_type}")

    ext = extract(model_output)
    if ext.extractor == "none" or not ext.span:
        return Verdict(
            item_id=item["id"],
            label="no_answer",
            extractor=ext.extractor,
            raw_span=ext.span,
            normalized_pred="",
        )

    pred_norm = normalize(ext.span)
    gold_norm = normalize(item["gold"]["canonical"])
    alts_norm = [normalize(a) for a in item["gold"].get("alternates", [])]

    # Try canonical first, then each alternate. The first hit is logged
    # so the readout can show which form the model matched on.
    try:
        if equivalent(pred_norm, gold_norm, gold_type):
            return Verdict(
                item_id=item["id"],
                label="correct",
                extractor=ext.extractor,
                raw_span=ext.span,
                normalized_pred=pred_norm,
                matched_alternate=None,
            )
        for alt in alts_norm:
            if equivalent(pred_norm, alt, gold_type):
                return Verdict(
                    item_id=item["id"],
                    label="correct",
                    extractor=ext.extractor,
                    raw_span=ext.span,
                    normalized_pred=pred_norm,
                    matched_alternate=alt,
                )
    except Exception as e:
        # Parser crashed on the model's output: this is an extraction
        # failure, not a wrong answer. Bucket separately.
        return Verdict(
            item_id=item["id"],
            label="extraction_failed",
            extractor=ext.extractor,
            raw_span=ext.span,
            normalized_pred=pred_norm,
            notes=[f"parser exception: {type(e).__name__}: {e}"],
        )

    return Verdict(
        item_id=item["id"],
        label="wrong",
        extractor=ext.extractor,
        raw_span=ext.span,
        normalized_pred=pred_norm,
    )


def summary(verdicts: list[Verdict]) -> dict:
    n = len(verdicts)
    counts = {"correct": 0, "wrong": 0, "no_answer": 0, "extraction_failed": 0}
    for v in verdicts:
        counts[v.label] += 1
    return {
        "n": n,
        **counts,
        "accuracy_strict": counts["correct"] / n if n else 0.0,
        # Report two accuracies: strict counts no_answer / extraction_failed
        # as wrong; lenient-extraction counts only wrong as wrong and shows
        # how many items the extractor dropped.
        "accuracy_if_extracted": (
            counts["correct"] / (n - counts["no_answer"] - counts["extraction_failed"])
            if (n - counts["no_answer"] - counts["extraction_failed"]) > 0 else 0.0
        ),
        "dropped_frac": (counts["no_answer"] + counts["extraction_failed"]) / n if n else 0.0,
    }
```

The summary deliberately reports **two accuracies**:

- `accuracy_strict` is the headline — the one you compare to a published benchmark.
- `accuracy_if_extracted` is a diagnostic — if it is much higher than `accuracy_strict`, the extractor is the bottleneck, not the model.
- `dropped_frac` is the honesty column — the fraction of items the extractor dropped. A paper that reports accuracy without this number is leaving a bug-detector off.

### 2.7 Reproduction manifest

```yaml
run_id: mini_math_v1_opus-4-7_2026-11-20
problem_set: mini_math_v1
problem_set_sha256: <sha256 of problems/mini_math_v1.jsonl>
grader_commit: <git sha of this repo>
sympy_version: "1.12"
model:
  id: claude-opus-4-7
  decoding:
    temperature: 0.0
    max_tokens: 1024
  system_prompt_sha256: <sha256 of the system prompt file>
seed: 20261120
cli: "python -m grader.grade --problems problems/mini_math_v1.jsonl --model claude-opus-4-7 --seed 20261120"
results:
  n: 25
  correct: 18
  wrong: 5
  no_answer: 1
  extraction_failed: 1
  accuracy_strict: 0.72
  accuracy_if_extracted: 0.783
  dropped_frac: 0.08
```

## 3. Validation steps

1. **Extractor property tests.** `test_extract.py` pins order (boxed > the-answer-is > final-line), brace balancing, last-match wins, empty-input behavior, and that stray tokens after the span (e.g., `"\\boxed{5}. Therefore..."`) do not pollute the extracted answer.
2. **Normalizer round-trip.** `normalize(normalize(x)) == normalize(x)` for every gold canonical and every alternate in the problem file. A normalizer that is not idempotent is a source of silent accuracy drift between runs.
3. **Alternates are self-consistent.** For every problem, every alternate is `equivalent(canonical, alternate, gold.type) == True`. A broken alternate is a silent false negative on any model that writes the "wrong" alternate.
4. **Unknown types are rejected.** A problem with `gold.type: "approximate"` fails CI. The grader never silently defaults to `string` equivalence.
5. **No substring fallback.** A test asserts that `"the answer is 4"` combined with gold `"4"` is correct, but `"the answer is 40"` combined with gold `"4"` is wrong. A substring fallback would pass the second.
6. **Separate buckets for `no_answer` and `extraction_failed`.** A test fires a known-crashing input at `_parse` (e.g., `\boxed{}`) and asserts the verdict label is `extraction_failed`, not `wrong`.
7. **Checksum pin.** `problems/checksums.sha256` is regenerated by CI and compared against the committed file.
8. **Determinism at temperature 0.** Two consecutive runs of the grader on the same cached model outputs produce the same list of `Verdict`s. Any instability points at a non-deterministic step in normalization (e.g., iterating over an unordered set).
9. **SymPy version pin.** `sympy_version` in the manifest is checked against the running environment at grade time. Equivalence can change between SymPy releases (`simplify` adds rules); the manifest documents which rule set produced the number.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a documented, tested measurement instrument** whose result is an audit trail, not a scalar.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Problems have `canonical`, `alternates`, and `type` as first-class fields | 2 | `problems/*.jsonl`; CI verifies alternates are equivalent to canonical. |
| R2 | Extractor is layered, tested, and traces which rule fired | 2 | `extract.py` returns `(span, extractor)`; `test_extract.py` pins order. |
| R3 | Normalization is idempotent and does not change semantics | 1 | `normalize(normalize(x)) == normalize(x)` on gold set; no lowercasing / no fraction simplification. |
| R4 | Equivalence dispatches by `gold.type`; no substring fallback | 2 | `equivalence.DISPATCH`; unknown type raises; "40 vs 4" wrong-answer test passes. |
| R5 | Verdict has `correct` / `wrong` / `no_answer` / `extraction_failed` as separate labels | 1 | Grader returns a `Verdict` dataclass; summary reports counts for each. |
| R6 | Report includes `accuracy_strict`, `accuracy_if_extracted`, and `dropped_frac` | 1 | `summary` output; manifest references all three. |
| R7 | Manifest pins problem checksum, grader commit, SymPy version, model id, seed | 1 | `reproduction/*.yaml`; CI rejects a missing field. |

**Passing bar:** 7 / 10. R4 is non-negotiable — a substring fallback makes every other improvement meaningless.

Reviewer checklist:

- [ ] Every `alternate` is equivalent to its `canonical` under the type's equivalence function.
- [ ] Every `gold.type` is in the dispatch table; unknown types fail CI.
- [ ] A test asserts `"40" is NOT equivalent to "4"` for `gold.type: number`.
- [ ] A `\boxed{...}` before `"the answer is ..."` extracts via `boxed`, not `the_answer_is`.
- [ ] The verdict buckets `no_answer` and `extraction_failed` are reported separately from `wrong`.
- [ ] `accuracy_if_extracted` is reported alongside `accuracy_strict`.
- [ ] `sympy_version` in the manifest matches the runtime.
- [ ] The problem file SHA matches `problems/checksums.sha256`.

## 5. Common mistakes

- **Substring equivalence.** `"4" in model_output` passes any item whose gold is `4` and whose model output contains `"4"` anywhere — including `"we started with 42 - 38 = 4, but that is wrong, the answer is 8"`. Dispatch by `gold.type` and never fall through.
- **First-boxed-wins instead of last-boxed-wins.** A model restates intermediate work: `"\\boxed{10} was my first guess; actually \\boxed{12}"`. First-wins extracts 10 and marks correct answers wrong. Last-wins extracts 12.
- **Regex of `"answer is ([0-9]+)"` without alternatives.** Misses `\frac{3}{4}`, `\sqrt{2}`, `-5`, `(1, 2)`. Use a layered chain: `boxed` → `the_answer_is` (phrase + arbitrary tail) → `final_line`.
- **Lowercasing in normalization.** A gold of `"X"` (a variable) becomes `"x"` and accidentally matches the model's lower-case `x`. Normalize whitespace and LaTeX cosmetics, not case.
- **Simplifying fractions in normalization.** The normalizer evaluates `"8/4"` to `"2"`, then SymPy equivalence trivially succeeds. The normalizer has done the model's work for it. Leave simplification to SymPy, which you can version.
- **Treating `no_answer` as wrong.** The model emitted a long chain of thought that was cut off before the final answer. Bucketing this as `wrong` hides a context-length / decoding bug as a model-quality bug.
- **Treating `extraction_failed` as wrong.** The model wrote a correct answer in a format the extractor did not handle. The number drops; the eval reports lower accuracy than the model deserves; worse, the error is a function of the extractor's taste, not the model's output.
- **Float tolerance absolute, not relative.** `1e-6` catches `pi ≈ 3.141593`, but misses `6.022e23 ≈ 6.022001e23`. Use `1e-6 * max(1, |a|, |b|)`.
- **Unpinned SymPy.** `simplify` gets new rules; `parse_latex` gets new coverage. A silent SymPy upgrade changes equivalence verdicts. Pin the version in the manifest and in CI.
- **Alternates copied from the same source as canonical.** `canonical = "4"`, `alternates = ["4"]`. The alternates list is now cosmetic. Alternates are for *semantically equivalent different forms* the model is likely to emit — `"4.0"`, `"2^2"`, `"\\frac{4}{1}"`.
- **No per-item audit trail.** Only the summary is saved. A reviewer asks "why did item mm-00012 count as wrong?" and the only answer is "rerun." Save the full `Verdict` list — `raw_span`, `normalized_pred`, `extractor`, `matched_alternate`, `notes`.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires the measurement instrument — here the extract-normalize-equivalence pipeline — to be documented, tested, and tied to an operational context; the SymPy-version pin and the `Verdict` trace are the direct operationalization for a math eval.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML08 Model Skewing** maps directly to a loose equivalence check: a substring-based grader biases the metric in favor of models that emit the gold token anywhere, which is a skew in the measurement, not in the model.
- MITRE ATLAS — <https://atlas.mitre.org/>. `Craft Adversarial Data` describes the technique that exploits a known grading rule — once an attacker learns an extractor's regex, they can nudge the reasoning to game it. The dispatch-by-type equivalence check is the narrowest control.

<!-- Local exercise context: the `mini_math_v1` set of 25 problems, the set of extractor rules (`boxed`, `the_answer_is`, `final_line`), the specific float tolerance (`1e-6 * max(1, |a|, |b|)`), and the six `gold.type` values (`number`, `expression`, `set`, `interval`, `tuple`, `string`) are illustrative defaults for a general-purpose math eval. Rewrite them for the gold-answer space of your own benchmark before adopting. Code-generation evaluation whose scoring is executable rather than symbolic is the subject of [exercise-01](../exercise-01-pass-at-k-with-sandbox-execution/SOLUTION.md); RAG evaluation whose scoring is grounded in a retrieved context is covered in [exercise-03](../exercise-03-rag-eval-with-ragas-and-trulens/SOLUTION.md); multimodal evaluation is in [exercise-04](../exercise-04-multimodal-vqa-and-grounding-eval/SOLUTION.md); the product-shaped harness that bundles all four is in [exercise-05](../exercise-05-product-shaped-eval-suite-design/SOLUTION.md). -->
