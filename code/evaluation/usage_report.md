# Usage Report

## Final full-dataset run
- Dataset processed: `dataset/deletion_requests.csv`
- Request rows: 518
- Output file: `output.csv` at the repository root
- Execution command: `python code/main.py`
- Result: structurally valid CSV generated successfully for all 518 requests

## Model usage
This implementation is a deterministic local generator and does not call external model providers.

- Providers used: none
- Model names: none
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0.0
- Estimated total cost: $0.00
- Estimated per-request cost: $0.00

## Important note on evaluation status
The current run confirms format correctness and output generation, but not hidden-answer deletion accuracy. The challenge is not considered fully verified until the evidence-backed decisions, policy logic, and hidden-case accuracy are validated against the full dataset and canonical answers.
