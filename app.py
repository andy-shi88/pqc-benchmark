from flask import Flask, jsonify
import time

app = Flask(__name__)


@app.route('/health-check', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Service is running'
    }), 200


@app.route('/generate-key', methods=['POST'])
def generate_key():
    """Generate key endpoint with time tracking"""
    start_time = time.time()
    
    # Simulate key generation work
    # Add your key generation logic here
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    return jsonify({
        'time_taken': f"{time_taken:.6f}",
        'operation': 'generate_key'
    }), 200

@app.route('/sign', methods=['POST'])
def sign():
    """Sign endpoint with time tracking"""
    start_time = time.time()
    
    # Simulate key generation work
    # Add your key generation logic here
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    return jsonify({
        'time_taken': f"{time_taken:.6f}",
        'operation': 'sign'
    }), 200

@app.route('/verify', methods=['POST'])
def verify():
    """Verify endpoint with time tracking"""
    start_time = time.time()
    
    # Simulate key generation work
    # Add your key generation logic here
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    return jsonify({
        'time_taken': f"{time_taken:.6f}",
        'operation': 'verify'
    }), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
