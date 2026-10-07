# LogAsis Datasets

## Overview

LogAsis supports open datasets for research and evaluation. All downloads are explicit and reproducible.

## Supported Datasets

### LogHub / LogPAI Datasets

| Dataset | Description | Labels |
|---------|-------------|--------|
| HDFS_v1 | HDFS distributed file system logs | Anomaly labels |
| BGL | Blue Gene/L supercomputer logs | Alert labels |
| HPC | High performance computing cluster logs | None |
| OpenSSH | OpenSSH authentication logs | None |
| Hadoop | Hadoop logs | None |
| Linux | Linux system logs | None |
| OpenStack | OpenStack logs | None |
| Spark | Spark logs | None |
| Thunderbird | Thunderbird logs | None |
| Windows | Windows event logs | None |
| Apache | Apache web server logs | None |
| Android | Android logs | None |
| ZooKeeper | ZooKeeper logs | None |

### Security Datasets

| Dataset | Description | Labels |
|---------|-------------|--------|
| ADFA-LD | Australian Defence Force Academy Linux intrusion detection | Attack labels |

## Download Commands

```bash
# Download a LogHub dataset
python tools/datasets/download_loghub.py --dataset HDFS_v1

# Verify dataset integrity
python tools/datasets/verify_dataset.py --dataset HDFS_v1

# Prepare dataset for training
python tools/datasets/prepare_dataset.py --dataset HDFS_v1
```

`download_loghub.py` writes dataset metadata (source, URL, license,
citation) without downloading repository archives silently. After you
place the log files in `data/datasets/<id>/`, re-run it to record
integrity hashes, then `verify_dataset.py` can detect later tampering.

## Dataset Metadata

Every dataset includes:
- source
- URL
- license
- citation
- version
- download date
- hash
- parser
- fields
- label availability

## License Compliance

- Datasets are NOT redistributed with the application
- Download scripts and metadata are stored instead
- Each dataset's license and academic-use restrictions are respected
- No silent multi-gigabyte downloads during application startup

## Training Data Pipeline

```bash
# Prepare training data: parses supported log files with the app's own
# parser stack and writes <prepared>/<id>/events.jsonl + metadata.json
python -m training.prepare --dataset HDFS_v1

# Generate deterministic ground-truth questions (count, comparison,
# timeline, relationship, negative, contradiction, unknown-field)
python -m training.generate_questions --dataset HDFS_v1

# Retrieval benchmark: Recall@K / MRR / F1 / latency of the index-backed
# retriever (no model provider required)
python -m training.benchmark --dataset HDFS_v1

# Full evaluation against model predictions
python -m training.evaluate --predictions preds.json --ground-truth data/prepared/HDFS_v1/questions.json
```

The same pipeline is available through the tools wrappers:

```bash
python tools/datasets/prepare_dataset.py --dataset HDFS_v1
python tools/datasets/verify_dataset.py --dataset HDFS_v1
```

`verify_dataset.py` re-hashes files against hashes recorded in
metadata.json (tamper detection) and validates the prepared copy's
`events_hash` and `record_count`. `training.validate_dataset` additionally
checks that train/validation/test split files share no questions.

## Train/Validation/Test Split

- Split by dataset and scenario where possible
- Never evaluate on the same examples used for generation/tuning
- Include completely unseen logs in the test set
- A model that answers different wording of the same memorized log is not demonstrating generalization
