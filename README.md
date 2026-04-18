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

#### Generate Key Pair
```bash
python app.py generate
```

#### Sign Data
```bash
python app.py sign
```

#### Verify Signature
```bash
python app.py verify
```

### With Docker

#### Generate Key Pair
```bash
docker run --rm pqc-benchmark python app.py generate
```

#### Sign Data
```bash
docker run --rm pqc-benchmark python app.py sign
```

#### Verify Signature
```bash
docker run --rm pqc-benchmark python app.py verify
```

### With Docker Compose

Docker Compose runs different resource-constrained scenarios. By default, each service runs the `generate` command. You can modify the command in docker-compose.yml or run specific commands:

```bash
# Run all scenarios with default command (generate)
docker-compose up

# Run specific scenario with custom command
docker-compose run --rm pqc-benchmark-unconstrained python app.py sign
docker-compose run --rm pqc-benchmark-moderate python app.py verify
docker-compose run --rm pqc-benchmark-extreme python app.py generate
```

## Resource Scenarios

- **Unconstrained**: 1.0 CPU, 512M memory
- **Moderate**: 0.5 CPU, 128M memory
- **Extreme**: 0.25 CPU, 64M memory

## Output

Each command outputs:
- Operation name
- Time taken (in seconds)
- Additional metrics (key/signature size, validation result)

## Notes

- Uses Dilithium2 post-quantum signature algorithm
- All time measurements are in seconds with 6 decimal precision
- Requires liboqs library with Python bindings
