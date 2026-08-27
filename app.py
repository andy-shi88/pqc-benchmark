import time
import statistics
import oqs
import tracemalloc
import csv
from datetime import datetime
from crypto import PQCrypto, RegularCrypto, RegularSignature, PQSignature
import gc
# Disable automatic garbage collection
gc.disable()


# Supported OQS KEM algorithms
SUPPORTED_PQ_KEM_ALGORITHMS = [
    'BIKE-L1',
    'HQC-1',
    'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024',
    'FrodoKEM-640-AES',
]
SUPPORTED_REG_KEM_ALGORITHMS = [
    'ECDH-X25519',
]

SUPPORTED_REG_SIGNATURE_ALGORITHMS = [
    'ECDSA-P256',
    'RSA-2048',
]

SUPPORTED_PQ_SIGNATURE_ALGORITHMS = [
    # CRYSTALS-Dilithium / ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
    # 'Dilithium2',     # Equivalent to ML-DSA-44 (NIST Level 2 security)
    # 'Dilithium3',     # Equivalent to ML-DSA-65 (NIST Level 3 security)
    # 'Dilithium5',     # Equivalent to ML-DSA-87 (NIST Level 5 security)
    
    # SPHINCS+ / SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
    # 'SPHINCS+-SHA2-128s-simple',  # Equivalent to SLH-DSA-128s (small signature variant)
    # 'SPHINCS+-SHA2-192s-simple',  # Equivalent to SLH-DSA-192s (small signature variant)
    # 'SPHINCS+-SHA2-256s-simple',  # Equivalent to SLH-DSA-256s (small signature variant)
]


def list_private_key_sizes():
    """List all private key sizes for all supported algorithms"""
    results = {
        'PQ_KEM': {},
        'REG_KEM': {},
        'REG_SIGNATURE': {},
        'PQ_SIGNATURE': {}
    }
    
    print("="*60)
    print("Private Key Sizes for All Supported Algorithms")
    print("="*60)
    
    # PQ KEM algorithms
    print("\n[Post-Quantum KEM Algorithms]")
    for algorithm in SUPPORTED_PQ_KEM_ALGORITHMS:
        try:
            pqc = PQCrypto(algorithm=algorithm)
            pqc.generate_key()
            private_key_size = len(pqc.secret_key)
            results['PQ_KEM'][algorithm] = private_key_size
            print(f"  {algorithm:<35} : {private_key_size:>6} bytes")
        except Exception as e:
            print(f"  {algorithm:<35} : Error - {e}")
            results['PQ_KEM'][algorithm] = None
    
    # Regular KEM algorithms
    print("\n[Regular KEM Algorithms]")
    for algorithm in SUPPORTED_REG_KEM_ALGORITHMS:
        try:
            reg_crypto = RegularCrypto(algorithm=algorithm)
            reg_crypto.generate_key()
            private_key_size = len(reg_crypto.secret_key)
            results['REG_KEM'][algorithm] = private_key_size
            print(f"  {algorithm:<35} : {private_key_size:>6} bytes")
        except Exception as e:
            print(f"  {algorithm:<35} : Error - {e}")
            results['REG_KEM'][algorithm] = None
    
    # Regular Signature algorithms
    print("\n[Regular Signature Algorithms]")
    for algorithm in SUPPORTED_REG_SIGNATURE_ALGORITHMS:
        try:
            reg_sig = RegularSignature(algorithm=algorithm)
            reg_sig.generate_key()
            private_key_size = len(reg_sig.secret_key)
            results['REG_SIGNATURE'][algorithm] = private_key_size
            print(f"  {algorithm:<35} : {private_key_size:>6} bytes")
        except Exception as e:
            print(f"  {algorithm:<35} : Error - {e}")
            results['REG_SIGNATURE'][algorithm] = None
    
    # PQ Signature algorithms
    print("\n[Post-Quantum Signature Algorithms]")
    for algorithm in SUPPORTED_PQ_SIGNATURE_ALGORITHMS:
        try:
            pq_sig = PQSignature(algorithm=algorithm)
            pq_sig.generate_key()
            private_key_size = len(pq_sig.secret_key)
            results['PQ_SIGNATURE'][algorithm] = private_key_size
            print(f"  {algorithm:<35} : {private_key_size:>6} bytes")
        except Exception as e:
            print(f"  {algorithm:<35} : Error - {e}")
            results['PQ_SIGNATURE'][algorithm] = None
    
    print("\n" + "="*60)
    
    return results

def run_benchmark(pqc, algorithm, iteration, warmpup_iterations, final_iterations, csv_filename):
    print(f"Iterations: {iteration}")
    print("Running operations...")
    rep = 5
    results = {
        "algorithm": algorithm,
        "iterations": iteration,
        "warmup_iterations": warmpup_iterations,
        "oom_errors": 0,
        "repetitions": []
    }
    for j in range(rep):
        tracemalloc.start()
        generate_timings = []
        sign_timings = []
        verify_timings = []
        for i in range(final_iterations):
            try:
                # Generate key
                gen_time = pqc.generate_key()
                # Encapsulate (sign_data method)
                sign_time, ciphertext = pqc.sign_data()
                # Decapsulate (verify_signature method)
                verify_time = pqc.verify_signature(signature=ciphertext)
                if i >= warmpup_iterations:  # Only record timings after warmup
                    generate_timings.append(gen_time)
                    sign_timings.append(sign_time)
                    verify_timings.append(verify_time)
            except MemoryError as e:
                results["oom_errors"] += 1
                print(f"  OOM Error at iteration {i + 1}: {e}")
                continue
            except Exception as e:
                print(f"  Error at iteration {i + 1}: {type(e).__name__}: {e}")
                continue
            
            if (i + 1) % 10 == 0:
                print(f"  Completed {i + 1}/{final_iterations} iterations")
        
        # Get memory info for this rep
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Calculate medians
        median_generate = statistics.median(generate_timings)
        median_sign = statistics.median(sign_timings)
        median_verify = statistics.median(verify_timings)
        
        # Calculate totals
        total_generate = sum(generate_timings)
        total_sign = sum(sign_timings)
        total_verify = sum(verify_timings)
        
        # Get sizes
        public_key_size = len(pqc.public_key)
        ciphertext_size = len(ciphertext)
        
        # Store results in dictionary
        rep_result = {
            "rep": j + 1,
            "generate_key": {
                "total_time": total_generate,
                "median_time": median_generate,
                "public_key_size": public_key_size
            },
            "encapsulate": {
                "total_time": total_sign,
                "median_time": median_sign,
                "ciphertext_size": ciphertext_size
            },
            "decapsulate": {
                "total_time": total_verify,
                "median_time": median_verify
            },
            "memory_current_mb": current / 10**6,
            "memory_peak_mb": peak / 10**6
        }
        results["repetitions"].append(rep_result)
        
        print(f"Completed repetition {j+1}/{rep}")

    # Print final results
    print("\n" + "="*50)
    print(f"Benchmark Results for {algorithm}")
    print("="*50)
    print(results)
    
    # Append results to CSV
    with open(csv_filename, 'a', newline='') as csvfile:
        fieldnames = [
            'algorithm', 'iterations', 'repetition',
            'generate_total_time', 'generate_median_time', 'public_key_size',
            'encapsulate_total_time', 'encapsulate_median_time', 'ciphertext_size',
            'decapsulate_total_time', 'decapsulate_median_time',
            'memory_current_mb', 'memory_peak_mb', 'oom_errors'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        for rep_result in results["repetitions"]:
            row = {
                'algorithm': results['algorithm'],
                'iterations': results['iterations'],
                'repetition': rep_result['rep'],
                'generate_total_time': rep_result['generate_key']['total_time'],
                'generate_median_time': rep_result['generate_key']['median_time'],
                'public_key_size': rep_result['generate_key']['public_key_size'],
                'encapsulate_total_time': rep_result['encapsulate']['total_time'],
                'encapsulate_median_time': rep_result['encapsulate']['median_time'],
                'ciphertext_size': rep_result['encapsulate']['ciphertext_size'],
                'decapsulate_total_time': rep_result['decapsulate']['total_time'],
                'decapsulate_median_time': rep_result['decapsulate']['median_time'],
                'memory_current_mb': rep_result['memory_current_mb'],
                'memory_peak_mb': rep_result['memory_peak_mb'],
                'oom_errors': results['oom_errors']
            }
            writer.writerow(row)
    
    print(f"Results appended to {csv_filename}")

def main():
    # Check if it is disabled
    print(f"GC: {gc.isenabled()}")  # Returns False
    print(f"supported sign: {oqs.get_supported_sig_mechanisms()}")
    print(f"supported kem: {oqs.get_supported_kem_mechanisms()}")
    import os
    os.makedirs('results', exist_ok=True)
    iteration = 100
    warmpup_iterations = 10
    final_iterations = iteration + warmpup_iterations
    sleep_time = 30  # seconds
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"results/benchmark_{timestamp}.csv"
    
    # Create CSV file and write header
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = [
            'algorithm', 'iterations', 'repetition',
            'generate_total_time', 'generate_median_time', 'public_key_size',
            'encapsulate_total_time', 'encapsulate_median_time', 'ciphertext_size',
            'decapsulate_total_time', 'decapsulate_median_time',
            'memory_current_mb', 'memory_peak_mb', 'oom_errors'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    # Create PQCrypto instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_PQ_KEM_ALGORITHMS):
        print(f"Running benchmark with algorithm: {algorithm}")
        pqc = PQCrypto(algorithm=algorithm)
        run_benchmark(pqc, algorithm, iteration, warmpup_iterations, final_iterations, csv_filename)
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_PQ_KEM_ALGORITHMS) - 1:
            print(f"\nSleeping {sleep_time} seconds before next algorithm...\n")
            time.sleep(sleep_time)
    
    # reguler KEM
    # Create RegularCrypto instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_REG_KEM_ALGORITHMS):
        pqc = RegularCrypto(algorithm=algorithm)
        print(f"Running benchmark with algorithm: {algorithm}")
        run_benchmark(pqc, algorithm, iteration, warmpup_iterations, final_iterations, csv_filename)
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_REG_KEM_ALGORITHMS) - 1:
            print(f"\nSleeping {sleep_time} seconds before next algorithm...\n")
            time.sleep(sleep_time)

    # regular signature
    # Create RegularSignature instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_REG_SIGNATURE_ALGORITHMS):
        pqc = RegularSignature(algorithm=algorithm)
        print(f"Running benchmark with algorithm: {algorithm}")
        run_benchmark(pqc, algorithm, iteration, warmpup_iterations, final_iterations, csv_filename)
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_REG_SIGNATURE_ALGORITHMS) - 1:
            print(f"\nSleeping {sleep_time} seconds before next algorithm...\n")
            time.sleep(sleep_time)

    # pq signature
    # Create PQSignature instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_PQ_SIGNATURE_ALGORITHMS):
        pqc = PQSignature(algorithm=algorithm)
        print(f"Running benchmark with algorithm: {algorithm}")
        run_benchmark(pqc, algorithm, iteration, warmpup_iterations, final_iterations, csv_filename)
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_PQ_SIGNATURE_ALGORITHMS) - 1:
            print(f"\nSleeping {sleep_time} seconds before next algorithm...\n")
            time.sleep(sleep_time)
    

if __name__ == '__main__':
    import sys
    
    # Check if user wants to list private key sizes
    if len(sys.argv) > 1 and sys.argv[1] == '--list-key-sizes':
        list_private_key_sizes()
    else:
        main()
