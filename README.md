# PQC Benchmark CLI

A command-line tool for benchmarking Post-Quantum Cryptography operations using liboqs (Dilithium2).

## Setup

### Local Development

1. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Docker Setup

Build the Docker image:
```bash
docker build -t pqc-benchmark .
```

## Running the Application

### Locally

The CLI supports three commands:

#### Run The Benchmark
```bash
python app.py
```


### With Docker

```bash
docker run --rm pqc-benchmark python app.py
```


### With Docker Compose

Docker Compose runs different resource-constrained scenarios. 

```bash
# Run all scenarios with default command (generate)
docker-compose up

# Run specific scenario with custom command
docker-compose run --rm pqc-benchmark-unconstrained python app.py
docker-compose run --rm pqc-benchmark-moderate python app.py
docker-compose run --rm pqc-benchmark-extreme python app.py
```

## Resource Scenarios

- **Unconstrained**: 1.0 CPU, 512M memory
- **Moderate**: 0.5 CPU, 128M memory
- **Extreme**: 0.25 CPU, 64M memory

## Output

Each command outputs a file mapped by docker-compose to ./results


### Output Data

- Statistic Tests

Statistic test are stored in `data/statistics/` and include:
- kruskal_summary.csv and dunn_summary.csv: Summary of the Kruskal-Wallis and Dunn's tests results, including p-values and significance levels.
- anova.csv: Summary of the ANOVA test results, including F-statistic and p-value.
- lmm.csv: Summary of the Linear Mixed Model results, including fixed effects estimates and significance levels.
- spearman_correlation.csv: Summary of the Spearman's rank correlation results, including correlation coefficients and p-values.


- Raw Data

This data is stored in `data/pqc_recap.xlsx`, this include compilation of all raw data collected during the benchmark, such as execution times, memory usage, and other relevant metrics for each scenario and operation type. Also includes all measurement requirement based on the defined scenarios (unconstrained, moderate, extreme) and operations (key generation, signing, verification) as stated in the assignment.


- Python Notebook

Stored in `data/komjar-pqc-report.ipynb`. Plots and visualizations are stored here.

This notebook is also used for generating statistical test and analysis from `data/pqc_recap.xlsx` and the results are stored in `data/statistics/` as mentioned above.