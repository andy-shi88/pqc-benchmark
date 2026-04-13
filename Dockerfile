FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Expose the application port
EXPOSE 5005

# Run the application
CMD ["python", "app.py"]
