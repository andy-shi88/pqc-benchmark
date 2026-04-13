# PQC Benchmark API

A simple Flask REST API for benchmarking Post-Quantum Cryptography operations.

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

Run with Docker Compose (recommended):
```bash
docker-compose up
```

Or build and run manually:
```bash
docker build -t pqc-benchmark .
docker run -p 5005:5005 pqc-benchmark
```

## Running the Application

### Locally
```bash
python app.py
```

### With Docker
```bash
docker-compose up
```

The API will be available at `http://localhost:5005`

## Endpoints

### GET /health-check
Health check endpoint that returns the service status.

**Example:**
```bash
curl http://localhost:5005/health-check
```

**Response:**
```json
{
  "status": "healthy",
  "message": "Service is running"
}
```

### POST /generate-key
Generates a key and returns the time taken for the operation.

**Example:**
```bash
curl -X POST http://localhost:5005/generate-key
```

**Response:**
```json
{
  "time_taken": "0.000012",
  "operation": "generate_key"
}
```

### POST /sign
Signs data and returns the time taken for the operation.

**Example:**
```bash
curl -X POST http://localhost:5005/sign
```

**Response:**
```json
{
  "time_taken": "0.000008",
  "operation": "sign"
}
```

### POST /verify
Verifies a signature and returns the time taken for the operation.

**Example:**
```bash
curl -X POST http://localhost:5005/verify
```

**Response:**
```json
{
  "time_taken": "0.000010",
  "operation": "verify"
}
```

## Notes

- All time measurements are in seconds with 6 decimal precision
- The server runs on port 5005 by default
- Debug mode is enabled for development
