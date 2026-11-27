# Practice 04 - Hashing

## Experiment artifacts

- raw.csv - raw hash performance measurements.
- avalanche.csv - avalanche effect measurements.
- report.json - validated experiment report.
- chart_throughput.png - throughput chart.
- chart_avalanche.png - avalanche effect chart.

## Experiment summary

- 280 raw performance measurements.
- 56 aggregated performance results.
- 700 avalanche trials.
- 42 correctness checks.
- Failed checks: 0.

## Reproduction

Run from a clean Git working tree:

    .\.venv\Scripts\python.exe benchmarks\hash_benchmark.py

The source_commit field identifies the source code commit used for the experiment.
