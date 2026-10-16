# Recorded run

A check makes no request (`http.json` is empty). `input.json` is the evidence
of `planted/clean.json`: made-up, a reader's whole output with no fault in it,
so every rule is judged. The fuel it uses is what one judgement costs.

`planted/` holds one fixture per rule with its fault planted, and the clean
case; `talos-catalog-tests/tests/planted_faults.rs` runs them.

`make check-catalog-fuel TEMPLATE=github-dependency-scan-check` runs the check on `input.json` and
fails if the fuel used is above 80% of the limit `talos.json` declares.
