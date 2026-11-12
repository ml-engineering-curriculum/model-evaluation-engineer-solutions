# exercise-05 — Canary Set Design — Solution

## 1. Solution overview

The exercise asks the learner to design a **canary set** — a small collection of synthetic items with properties that let the benchmark team *detect, after the fact, whether the benchmark leaked into some model's training corpus*. The reference answer has four parts:

1. A **threat model** — what we are trying to detect and what we are not.
2. A **canary construction recipe** — how canaries are generated so that memorization is detectable but accidental contamination is not confused with real training.
3. A **probe protocol** — how we test a candidate model for canary recall, with controls.
4. A **governance wrapper** — where canaries live, who sees them, when they are rotated, how we respond to a positive detection.

This maps to the NIST AI RMF `MEASURE` and `MANAGE` functions — canaries are the measurement artifact that makes benchmark leakage detectable, and a response plan is what turns the signal into action ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)). The adversarial framing is on the OWASP ML Top 10 (**ML02 Data Poisoning**, **ML03 Model Inversion**, **ML06 Corrupted Packages**) and on MITRE ATLAS (**Verify Attack**, **Exfiltrate via Model**) — canaries are detection evidence for those tactics regardless of whether the contamination was adversarial or accidental ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/); [MITRE ATLAS](https://atlas.mitre.org/)).

Canaries complement, but do not replace, the direct contamination pipeline from exercise-03. The direct pipeline needs access to a candidate training corpus; canaries work even when the corpus is a black box.

## 2. Implementation

### 2.1 Threat model

What we want to detect:

- A model whose training corpus ingested our benchmark distribution directly (crawl, mirror, redistribution).
- A model whose training corpus ingested a leaderboard dump that contained our benchmark items alongside gold labels.
- Accidental inclusion via a public mirror we did not authorize.

What we explicitly cannot detect with canaries alone:

- Paraphrased or translated versions of real benchmark items (that is stage 3 of exercise-03).
- Semantic contamination (model trained on items that share the same facts via a different route).
- Models that saw the canary strings but did not memorize them (small-scale fine-tuning, strong regularization).

Writing the threat model down matters. A canary set that over-claims — "no recall means no training" — is worse than one that is scoped.

### 2.2 Canary construction recipe

A canary item must satisfy five properties:

**C1 Unique.** The canary text must have near-zero prior probability under any reasonable language model that did not see it. Random high-entropy strings (GUIDs, nonce sentences with rare-word combinations) are the cheapest route. Natural-language-looking canaries work too and are harder to filter out before training.

**C2 Stable under crawling.** The canary must survive HTML scraping, dedup, and tokenizer quirks. That means: avoid rare Unicode, avoid excessive whitespace, avoid formatting that scraping heuristics may strip.

**C3 Probe-able.** The canary must support a deterministic recall probe. The standard shape is a **prompt / continuation** split: the prompt is a short lead-in that is itself not unique, and the continuation is the unique part the model would have to emit. Scoring is exact match on the continuation (or, with a tokenizer-aware normalization, at the token level).

**C4 Attributable.** Each canary carries a per-benchmark marker so that a positive recall unambiguously points at *this* benchmark's leak. "ZX-fact-" prefixes or embedded hashes of the benchmark version are enough.

**C5 Non-trivial.** The canary continuation must be long enough that random guessing has a vanishingly small prior probability. For a vocabulary of `V` tokens and a continuation of `L` tokens, random-guess prior ≈ `1 / V^L`. For realistic transformers (`V ≈ 32,000`), `L = 20` tokens is ample.

A worked canary item:

```json
{
  "canary_id": "factuality-qa/canary/0042",
  "version": "2.0.0",
  "variant": "nl-synthetic",
  "prompt": "According to the proceedings of the Bainbridge Committee on Hydrology (1963), ",
  "continuation": "the three measured discharge coefficients at the Marvanook weir were 0.4172, 0.4188, and 0.4203, as recorded by observer ZX-fact-42-7af9.",
  "token_length_continuation": 42,
  "random_guess_prior_log10": -170,
  "injection": {
    "distribution_channels": ["docs/canaries-public.jsonl", "examples/readme-demo-items.md"],
    "public": true,
    "redistribution_tracked": true
  },
  "probe": {
    "mode": "completion",
    "match": "normalized_exact",
    "temperature": 0
  }
}
```

Notes:

- The lead-in ("Bainbridge Committee...") is plausibly natural text, so it will not trip scrapers' dedup/boilerplate filters.
- The continuation contains a benchmark marker (`ZX-fact-42-7af9`) and improbable specific numbers.
- The entity ("Bainbridge Committee", "Marvanook weir") is fabricated. Canaries should not invoke real people or places — a model memorizing those would be a legitimate feature, not a signal of leakage. If the fabrication risks libel or confusion, confine canaries to visibly synthetic markers (e.g. "ZX-fact-42-7af9 reports value 0.4172").

#### Canary variants

Mix at least two variants so that one filter cannot eliminate them all:

| Variant | Example | What it guards |
|---|---|---|
| `nl-synthetic` | Natural-looking text with fabricated entities and improbable numbers. | Crawlers that strip obvious nonce strings. |
| `nonce-id` | Pure random-token strings embedded in context (`ref-id: ZXPL-7af9-...`). | Any scraper that keeps IDs verbatim. |
| `qa-pair` | A question with a unique answer that only this benchmark provides. | Leaderboard dumps where (item, label) pairs leak together. |

### 2.3 Where canaries live

A canary is only useful if it was *in the training corpus* of a candidate model. Place canaries in channels that any plausible crawl would hit:

- In the public benchmark distribution file (`items.jsonl`) alongside real items — mix is enough; the ratio does not matter much because recall is per-item.
- In the benchmark's public README / landing page, in at least one worked example.
- In any sample fixtures the maintainers ship ("here's one eval item so you can test your loader").
- Optionally mirrored to a tracked static path the team can later cite as the canonical crawl target.

Track every distribution channel in the canary record (`injection.distribution_channels`). On a positive detection, the first forensic question is "which channel might have been crawled?" and the record has to answer it.

#### What *not* to do

- Do **not** keep the canary set private. Private canaries only catch adversaries you were going to lose to anyway — crawlers that scrape authorized mirrors. Mixed-use: public canaries detect accidental ingestion; a smaller set of **held-out private canaries** tests whether the model also saw unpublished variants (this detects more targeted leakage).
- Do **not** mark the canaries with HTML comments that say "DO NOT TRAIN." Serious crawlers ignore these; it mostly helps good-faith operators and does not change the detection posture.

### 2.4 Probe protocol

A probe is a *controlled* test. The procedure:

1. **Positive set** = the canaries listed in the canary file at the time of the candidate model's training cutoff.
2. **Negative-control set** = canaries authored *after* the candidate model's training cutoff. The model cannot have seen these. They have the same construction recipe as the positive set.
3. **Run.** For each canary in both sets, prompt the model with `prompt` at temperature 0 and compare the first `token_length_continuation` tokens of the output against `continuation`, using the normalization declared in `probe.match`.
4. **Signal.**
   - Positive-set recall rate: `r_pos` = fraction of positive canaries where normalized exact match succeeds.
   - Negative-set recall rate: `r_neg` = same on the negative-control set.
   - `r_neg` **must be ~0**. If it is not, the construction is leaky (e.g. the continuation is too predictable) and the canary set has to be regenerated.
   - A non-zero `r_pos` with `r_neg ≈ 0` is evidence of ingestion. The strength of the evidence scales with `r_pos` and with how improbable each canary continuation is a priori.

5. **Report.** Record model identifier, model version, probe date, `r_pos`, `r_neg`, canary variant breakdown, and the random-guess prior for the longest canary. "No recall" is a result; publish it.

Pseudo-code:

```python
# canary_probe.py
def probe(model, canaries):
    hits = 0
    per_variant = defaultdict(lambda: [0, 0])
    for c in canaries:
        completion = model.complete(c.prompt, max_tokens=c.token_length_continuation,
                                    temperature=0.0)
        matched = normalize(completion).startswith(normalize(c.continuation))
        per_variant[c.variant][1] += 1
        if matched:
            hits += 1
            per_variant[c.variant][0] += 1
    return hits / len(canaries), per_variant
```

### 2.5 Response plan

A positive recall is not, by itself, a verdict that the model owner trained on your benchmark. The policy must say what the next step is.

| Signal | Interpretation | Action |
|---|---|---|
| `r_pos ≈ 0`, `r_neg ≈ 0` | No evidence of ingestion. | Publish the result; include in regression suite. |
| `r_pos > 0`, `r_neg ≈ 0`, variant = `nonce-id` only | Likely public-mirror ingestion of raw canary IDs. | Private notification to the model owner with evidence; invite response; publish on a declared timeline (e.g. 30 days) if no acknowledgment. |
| `r_pos > 0` across multiple variants, including `qa-pair` | Likely ingested the labeled benchmark. | Treat eval scores on this model as *suspect*: mark leaderboard entries, prohibit new submissions against this version, trigger a benchmark `MAJOR` bump with regenerated items (see exercise-04). |
| `r_pos ≈ 0`, `r_neg > 0` | Canary construction is leaky. | **Do not publish.** Regenerate the affected canaries; investigate why the "unseen" items are recalled (likely low prior-probability continuation). |
| Any case where the model owner has pre-committed to a "no benchmark training" statement | Treat as policy violation evidence. | Share evidence privately first; coordinate disclosure per the team's responsible-disclosure policy. |

### 2.6 Rotation

Canaries age poorly. Once a canary has been publicly probed and reported, model operators learn to filter the exact strings out. Rotate:

- On every benchmark MAJOR (see exercise-04). The new MAJOR gets a fresh canary set; the old canaries are retained for retrospective probes against models trained before the MAJOR.
- Out-of-band if a canary is directly exposed by a probe writeup.

Each canary file is versioned with the benchmark. The retired canary file is kept (with retirement date) so that probes of older models remain reproducible.

## 3. Validation steps

1. **Negative-control check.** Run the probe with the post-cutoff canary set. `r_neg` must be at or near zero. If it is not, the construction is leaky and the set is not ready.
2. **Prior-probability sanity.** For the longest canary, log the probability under a public base model that cannot have seen the canaries. Random-ish should be at or below `V^(-L)`. If a public base model assigns the continuation a non-trivial probability, the continuation is too predictable — regenerate.
3. **Scrape-survival check.** Fetch each distribution channel through a realistic scraping stack (headless browser + boilerplate stripper). Confirm the canary strings survive. If they are stripped, the canaries are not in any training corpus either.
4. **Attributability test.** Insert a single canary into a toy training run of a small model. Probe. The recall should attribute the hit to *this* benchmark (via the marker in the continuation) with no ambiguity.
5. **Rotation dry-run.** Walk the rotation path: generate new canaries, publish them for the next version, retire the old file with retirement date. Confirm old probes on older models still reproduce.
6. **Response-plan tabletop.** Walk the response table against a mock positive detection. Every branch must have a named owner and a declared timeline.

## 4. Rubric

Scored out of 10.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Threat model is written down with explicit scope | 1 | Document names what canaries detect *and* what they do not. |
| R2 | Canary construction meets C1–C5 | 2 | Each property is defensible for the submitted set: uniqueness, crawl-survival, probe design, attribution marker, length-vs-prior math. |
| R3 | At least two canary variants | 1 | File shows both `nl-synthetic` and `nonce-id` (or equivalent). |
| R4 | Distribution channels are tracked per canary | 1 | `injection.distribution_channels` is populated and matches committed files. |
| R5 | Probe includes a negative-control set | 2 | Post-cutoff canaries exist, probe reports both `r_pos` and `r_neg`. A probe report with only `r_pos` fails this check. |
| R6 | Response plan is a decision table, not prose | 1 | Table maps signal → action with named owners. |
| R7 | Rotation policy is bound to the versioning policy | 1 | Canary file is bumped on benchmark MAJOR; retired files are retained. |
| R8 | Probe is reproducible | 1 | `canary_probe.py` or equivalent, plus a committed example output on a reference model. |

**Passing bar:** 7 / 10. R2 and R5 are mandatory — a canary without a negative control is not a measurement.

### Review checklist

- [ ] Threat model names the attacks in scope and out of scope.
- [ ] `r_neg` on the committed negative-control set is near zero.
- [ ] Each canary carries an attributable marker.
- [ ] Distribution channels listed; files actually contain the canaries.
- [ ] Response plan names owners and timelines.
- [ ] Rotation ties to the benchmark versioning policy.
- [ ] Probe script runs end-to-end on a reference model.

## 5. Common mistakes

- **No negative control.** Reporting `r_pos` alone is not evidence of ingestion; the model may recall any low-prior continuation at some rate. Publish `r_neg`.
- **Private-only canaries.** Private canaries catch adversaries who scrape unauthorized mirrors. Accidental ingestion happens from authorized mirrors. Public *and* private is the mix.
- **Canaries indistinguishable from real items.** If the canary looks like a real benchmark item, a positive recall cannot be attributed: it might just be contamination from the real item. Keep the marker visible to the probe (even if subtle enough to survive scraping).
- **Tiny continuations.** A 3-token continuation has too high a random-guess prior. Aim for ≥ 20 tokens.
- **Memorizing real entities.** Canary text that references real people / places / events risks libel and makes recall ambiguous. Prefer fabricated entities with explicit synthetic markers.
- **Treating one positive canary as proof.** One hit at the detection limit is weak evidence. Report rates and intervals.
- **No rotation.** A canary set that never changes becomes a public filter list. Rotate on MAJOR.
- **Silent response.** Finding evidence of contamination without a response plan is not a program; it is a draft tweet.
- **No reproducibility.** A probe that only the authors can run is not an eval. Commit the script.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. `MEASURE` 2.3 (validity and reliability of measurement), `MANAGE` 4.1 (ongoing monitoring) — canaries operationalize both.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. ML02 (Data Poisoning), ML03 (Model Inversion / Membership Inference), ML06 (Corrupted Packages). Canary recall is a membership-style test with benign intent.
- MITRE ATLAS — <https://atlas.mitre.org/>. Verify Attack and Exfiltration via ML Inference tactics; canary probes are a defender's analogue of the same measurement primitives.
- Semantic Versioning 2.0.0 — <https://semver.org/>. Underpins the rotation policy via the exercise-04 versioning scheme.

<!-- Local exercise context: specific thresholds (continuation length ≥ 20 tokens, 30-day disclosure window, canary mix with at least two variants) are illustrative defaults. A real deployment should pick numbers backed by its own tokenizer, its own crawl-survival experiments, and its own disclosure policy. -->
