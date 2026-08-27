FROM ubuntu:22.04

# Install Python and build dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    cmake \
    libssl-dev \
    git \
    ninja-build \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/python3 /usr/bin/python

# Build and install liboqs from source
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    cd / && \
    rm -rf /tmp/liboqs

# Set working directory
WORKDIR /app

# Set environment variable for liboqs library path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY crypto/ ./crypto/

# Default command shows help
CMD ["python3", "app.py"]
