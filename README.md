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

