import time
import statistics
import oqs
import tracemalloc
import csv
from datetime import datetime
from crypto import PQCrypto, RegularCrypto, RegularSignature, PQSignature

# Supported OQS KEM algorithms
SUPPORTED_PQ_KEM_ALGORITHMS = [
    'BIKE-L1',
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
    'Dilithium2',     # Equivalent to ML-DSA-44 (NIST Level 2 security)
    'Dilithium3',     # Equivalent to ML-DSA-65 (NIST Level 3 security)
    'Dilithium5',     # Equivalent to ML-DSA-87 (NIST Level 5 security)
    
    # SPHINCS+ / SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
    'SPHINCS+-SHA2-128s-simple',  # Equivalent to SLH-DSA-128s (small signature variant)
    'SPHINCS+-SHA2-192s-simple',  # Equivalent to SLH-DSA-192s (small signature variant)
    'SPHINCS+-SHA2-256s-simple',  # Equivalent to SLH-DSA-256s (small signature variant)
]


def main():
    print(f"supported sign: {oqs.get_supported_sig_mechanisms()}")
    import os
    os.makedirs('results', exist_ok=True)
    
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
        pqc = PQCrypto(algorithm=algorithm)
        iterations = 100
        print(f"Running benchmark with algorithm: {algorithm}")
        print(f"Iterations: {iterations}")
        print()
        # Track timings for each operation
        generate_timings = []
        sign_timings = []
        verify_timings = []
        print("Running operations...")
        rep = 5
        results = {
            "algorithm": algorithm,
            "iterations": iterations,
            "oom_errors": 0,
            "repetitions": []
        }
        tracemalloc.start()
        for j in range(rep):
            for i in range(iterations):
                try:
                    # Generate key
                    gen_time = pqc.generate_key()
                    generate_timings.append(gen_time)
                    
                    # Encapsulate (sign_data method)
                    sign_time, ciphertext = pqc.sign_data()
                    sign_timings.append(sign_time)
                    
                    # Decapsulate (verify_signature method)
                    verify_time = pqc.verify_signature(signature=ciphertext)
                    verify_timings.append(verify_time)
                except MemoryError as e:
                    results["oom_errors"] += 1
                    print(f"  OOM Error at iteration {i + 1}: {e}")
                    continue
                except Exception as e:
                    print(f"  Error at iteration {i + 1}: {type(e).__name__}: {e}")
                    continue
                
                if (i + 1) % 10 == 0:
                    print(f"  Completed {i + 1}/{iterations} iterations")
            
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
                }
            }
            results["repetitions"].append(rep_result)
            
            print(f"Completed repetition {j+1}/{rep}")
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Add memory info to results
        results["memory_current_mb"] = current / 10**6
        results["memory_peak_mb"] = peak / 10**6

        # Print final results
        print("\n" + "="*50)
        print(f"Benchmark Results for {algorithm}")
        print("="*50)
        print(f"Memory -> Current: {current / 10**6:.2f} MB; Peak: {peak / 10**6:.2f} MB")
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
                    'memory_current_mb': results['memory_current_mb'],
                    'memory_peak_mb': results['memory_peak_mb'],
                    'oom_errors': results['oom_errors']
                }
                writer.writerow(row)
        
        print(f"Results appended to {csv_filename}")
        
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_PQ_KEM_ALGORITHMS) - 1:
            print(f"\nSleeping 3 seconds before next algorithm...\n")
            time.sleep(3)
    
    # reguler KEM
    # Create RegularCrypto instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_REG_KEM_ALGORITHMS):
        pqc = RegularCrypto(algorithm=algorithm)
        iterations = 100
        print(f"Running benchmark with algorithm: {algorithm}")
        print(f"Iterations: {iterations}")
        print()
        # Track timings for each operation
        generate_timings = []
        sign_timings = []
        verify_timings = []
        print("Running operations...")
        rep = 5
        results = {
            "algorithm": algorithm,
            "iterations": iterations,
            "oom_errors": 0,
            "repetitions": []
        }
        tracemalloc.start()
        for j in range(rep):
            for i in range(iterations):
                try:
                    # Generate key
                    gen_time = pqc.generate_key()
                    generate_timings.append(gen_time)
                    
                    # Encapsulate (sign_data method)
                    sign_time, ciphertext = pqc.sign_data()
                    sign_timings.append(sign_time)
                    
                    # Decapsulate (verify_signature method)
                    verify_time = pqc.verify_signature(signature=ciphertext)
                    verify_timings.append(verify_time)
                except MemoryError as e:
                    results["oom_errors"] += 1
                    print(f"  OOM Error at iteration {i + 1}: {e}")
                    continue
                except Exception as e:
                    print(f"  Error at iteration {i + 1}: {type(e).__name__}: {e}")
                    continue
                
                if (i + 1) % 10 == 0:
                    print(f"  Completed {i + 1}/{iterations} iterations")
            
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
                }
            }
            results["repetitions"].append(rep_result)
            
            print(f"Completed repetition {j+1}/{rep}")
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Add memory info to results
        results["memory_current_mb"] = current / 10**6
        results["memory_peak_mb"] = peak / 10**6

        # Print final results
        print("\n" + "="*50)
        print(f"Benchmark Results for {algorithm}")
        print("="*50)
        print(f"Memory -> Current: {current / 10**6:.2f} MB; Peak: {peak / 10**6:.2f} MB")
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
                    'memory_current_mb': results['memory_current_mb'],
                    'memory_peak_mb': results['memory_peak_mb'],
                    'oom_errors': results['oom_errors'],
                }
                writer.writerow(row)
        
        print(f"Results appended to {csv_filename}")
        
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_REG_KEM_ALGORITHMS) - 1:
            print(f"\nSleeping 3 seconds before next algorithm...\n")
            time.sleep(3)

    # regular signature
    # Create RegularSignature instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_REG_SIGNATURE_ALGORITHMS):
        pqc = RegularSignature(algorithm=algorithm)
        iterations = 100
        print(f"Running benchmark with algorithm: {algorithm}")
        print(f"Iterations: {iterations}")
        print()
        # Track timings for each operation
        generate_timings = []
        sign_timings = []
        verify_timings = []
        print("Running operations...")
        rep = 5
        results = {
            "algorithm": algorithm,
            "iterations": iterations,
            "oom_errors": 0,
            "repetitions": []
        }
        tracemalloc.start()
        for j in range(rep):
            for i in range(iterations):
                try:
                    # Generate key
                    gen_time = pqc.generate_key()
                    generate_timings.append(gen_time)
                    
                    # Encapsulate (sign_data method)
                    sign_time, ciphertext = pqc.sign_data()
                    sign_timings.append(sign_time)
                    
                    # Decapsulate (verify_signature method)
                    verify_time = pqc.verify_signature(signature=ciphertext)
                    verify_timings.append(verify_time)
                except MemoryError as e:
                    results["oom_errors"] += 1
                    print(f"  OOM Error at iteration {i + 1}: {e}")
                    continue
                except Exception as e:
                    print(f"  Error at iteration {i + 1}: {type(e).__name__}: {e}")
                    continue
                
                if (i + 1) % 10 == 0:
                    print(f"  Completed {i + 1}/{iterations} iterations")
            
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
                }
            }
            results["repetitions"].append(rep_result)
            
            print(f"Completed repetition {j+1}/{rep}")
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Add memory info to results
        results["memory_current_mb"] = current / 10**6
        results["memory_peak_mb"] = peak / 10**6

        # Print final results
        print("\n" + "="*50)
        print(f"Benchmark Results for {algorithm}")
        print("="*50)
        print(f"Memory -> Current: {current / 10**6:.2f} MB; Peak: {peak / 10**6:.2f} MB")
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
                    'memory_current_mb': results['memory_current_mb'],
                    'memory_peak_mb': results['memory_peak_mb'],
                    'oom_errors': results['oom_errors']
                }
                writer.writerow(row)
        
        print(f"Results appended to {csv_filename}")
        
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_REG_SIGNATURE_ALGORITHMS) - 1:
            print(f"\nSleeping 3 seconds before next algorithm...\n")
            time.sleep(3)

    # pq signature
    # Create PQSignature instance with specified algorithm    
    for algo_idx, algorithm in enumerate(SUPPORTED_PQ_SIGNATURE_ALGORITHMS):
        pqc = PQSignature(algorithm=algorithm)
        iterations = 100
        print(f"Running benchmark with algorithm: {algorithm}")
        print(f"Iterations: {iterations}")
        print()
        # Track timings for each operation
        generate_timings = []
        sign_timings = []
        verify_timings = []
        print("Running operations...")
        rep = 5
        results = {
            "algorithm": algorithm,
            "iterations": iterations,
            "oom_errors": 0,
            "repetitions": []
        }
        tracemalloc.start()
        for j in range(rep):
            for i in range(iterations):
                try:
                    # Generate key
                    gen_time = pqc.generate_key()
                    generate_timings.append(gen_time)
                    
                    # Encapsulate (sign_data method)
                    sign_time, ciphertext = pqc.sign_data()
                    sign_timings.append(sign_time)
                    
                    # Decapsulate (verify_signature method)
                    verify_time = pqc.verify_signature(signature=ciphertext)
                    verify_timings.append(verify_time)
                except MemoryError as e:
                    results["oom_errors"] += 1
                    print(f"  OOM Error at iteration {i + 1}: {e}")
                    continue
                except Exception as e:
                    print(f"  Error at iteration {i + 1}: {type(e).__name__}: {e}")
                    continue
                
                if (i + 1) % 10 == 0:
                    print(f"  Completed {i + 1}/{iterations} iterations")
            
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
                }
            }
            results["repetitions"].append(rep_result)
            
            print(f"Completed repetition {j+1}/{rep}")
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Add memory info to results
        results["memory_current_mb"] = current / 10**6
        results["memory_peak_mb"] = peak / 10**6

        # Print final results
        print("\n" + "="*50)
        print(f"Benchmark Results for {algorithm}")
        print("="*50)
        print(f"Memory -> Current: {current / 10**6:.2f} MB; Peak: {peak / 10**6:.2f} MB")
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
                    'memory_current_mb': results['memory_current_mb'],
                    'memory_peak_mb': results['memory_peak_mb'],
                    'oom_errors': results['oom_errors']
                }
                writer.writerow(row)
        
        print(f"Results appended to {csv_filename}")
        
        # Sleep 30 seconds between algorithms (except after the last one)
        if algo_idx < len(SUPPORTED_PQ_SIGNATURE_ALGORITHMS) - 1:
            print(f"\nSleeping 3 seconds before next algorithm...\n")
            time.sleep(3)
    

if __name__ == '__main__':
    main()
