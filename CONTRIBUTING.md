# Contributing

Thanks for helping. This is a small, security-sensitive library, so the
contribution bar is high on correctness and deliberately low on ceremony.

## Ground rules

- **No dependencies.** The whole point is that this runs anywhere Python runs
  with nothing installed. A `requirements.txt` entry is a blocking review
  comment.
- **No magic numbers in algorithm code.** Every constant belongs in
  `params.py`. If you need a new one, add it there with a citation to the
  specification.
- **Cite the algorithm.** Every function that implements a FIPS 203 or FIPS 204
  step should name it, so a reviewer can check it against the spec.
- **Standard library only.** That includes the tests and the tooling.

## Getting set up

```bash
git clone https://github.com/iamsandeshdhital/QuantumPost.git
cd QuantumPost
python -m quantumpost self-test
python -m unittest discover -s tests -v
```

No build step, no virtualenv requirement, no toolchain to install.

## Making a change

1. Open an issue first for anything non-trivial, so we agree on the approach
   before you spend the time.
2. Work on a branch.
3. Add tests. A change to a cryptographic primitive without a test that would
   have caught the bug will not be merged.
4. Run the full suite and `self-test`.
5. If you touched ML-DSA key generation, run `tools/check_acvp.py` against the
   NIST vectors — it must still report 75/75.

## Style

Follow the surrounding code. Concretely:

- type annotations on public functions;
- a docstring on every public function that says *what it computes*, not what the
  code obviously does;
- comments that explain **why**, never what;
- no commented-out code;
- keep lines under 100 characters.

## What we will not merge

- Anything that adds a runtime dependency.
- Anything that removes a conformance test to make CI green.
- A primitive that has not been checked against the specification.
- Speed "optimisations" that change behaviour. Pure Python is already the slow
  option; correctness is the product.

## Security

Do not open a public issue for a security problem. See
[SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the MIT licence that covers the repository.