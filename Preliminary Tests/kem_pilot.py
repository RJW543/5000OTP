import oqs
import time
import statistics
import psutil
import csv
import os
import subprocess

KEM_ALG = "Kyber768"  # The NIST Level 3 Standard
DURATION_SECONDS = 10  # How long to run the throughput stress test
SHARED_SECRET_SIZE = 32 # Bytes (Standard for Kyber768)

def print_header(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def check_entropy_speed():
    """Step 1: The Entropy Bottleneck Check"""
    print_header("Step 1: Hardware Entropy Check (/dev/hwrng)")
    
    try:
        start = time.time()
        # Read 100 blocks of 10k
        subprocess.run(
            ["dd", "if=/dev/hwrng", "of=/dev/null", "bs=1024", "count=10000"], 
            stderr=subprocess.PIPE, check=True
        )
        end = time.time()
        
        total_bytes = 1024 * 10000
        duration = end - start
        speed_mb_s = (total_bytes / duration) / (1024*1024)
        
        print(f"[-] HRNG Read Speed: {speed_mb_s:.2f} MB/s")
        if speed_mb_s > 0.5:
            print("[PASS] Entropy source is faster than KEM requirements.")
        else:
            print("[WARN] Entropy source might be a bottleneck.")
            
        return speed_mb_s
    except Exception as e:
        print(f"[ERROR] Could not check entropy: {e}")
        return 0

def benchmark_latency():
    """Step 2: Latency Distribution (Real-time feasibility)"""
    print_header("Step 2: Latency Benchmarking (Single Op)")
    
    times = []
    print(f"[-] Running 1,000 single iterations of {KEM_ALG}...")
    
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        for _ in range(1000):
            t0 = time.perf_counter_ns()
            
            # The Full Handshake: Alice KeyGen -> Bob Encap -> Alice Decap
            # This generates ONE shared secret (OTP chunk)
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            shared_secret_dec = kem.decap_secret(ciphertext)
            
            t1 = time.perf_counter_ns()
            times.append((t1 - t0) / 1_000_000) # Convert ns to ms

    avg_lat = statistics.mean(times)
    p95_lat = statistics.quantiles(times, n=20)[18] # 95th percentile
    p99_lat = statistics.quantiles(times, n=100)[98] # 99th percentile
    
    print(f"[-] Average Latency: {avg_lat:.3f} ms")
    print(f"[-] 99% Latency <  {p99_lat:.3f} ms")
    
    return avg_lat, p99_lat

def benchmark_throughput():
    """Step 3 & 4: Max Throughput & CPU Cost"""
    print_header(f"Step 3: Stress Test ({DURATION_SECONDS}s Loop)")
    
    iterations = 0
    start_time = time.time()
    
    # Monitor CPU before starting
    cpu_start = psutil.cpu_percent(interval=1)
    
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        # Run loop until time is up
        while (time.time() - start_time) < DURATION_SECONDS:
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            shared_secret_dec = kem.decap_secret(ciphertext)
            iterations += 1
            
    end_time = time.time()
    cpu_end = psutil.cpu_percent(interval=None) # Instant check
    
    total_time = end_time - start_time
    ops_per_sec = iterations / total_time
    # 32 bytes is the standard shared secret size for Kyber
    bytes_per_sec = ops_per_sec * SHARED_SECRET_SIZE 
    kb_per_sec = bytes_per_sec / 1024
    
    print(f"[-] Total Iterations: {iterations}")
    print(f"[-] OPS (Keys/sec):   {ops_per_sec:.2f}")
    print(f"[-] OTP Generation:   {kb_per_sec:.2f} KB/s")
    print(f"[-] CPU Usage End:    {cpu_end}%")
    
    return kb_per_sec, cpu_end

def save_report(entropy, latency, throughput, cpu):
    filename = "kem_pilot_results.csv"
    file_exists = os.path.isfile(filename)
    
    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Algorithm", "Entropy_MBs", "Avg_Latency_ms", "Throughput_KBs", "CPU_Usage_Pct"])
        
        writer.writerow([time.ctime(), KEM_ALG, f"{entropy:.2f}", f"{latency:.3f}", f"{throughput:.2f}", f"{cpu:.1f}"])
    
    print_header("Results Saved")
    print(f"Data saved to {filename}")
    print("This file contains the raw data")

def main():
    print(f"Starting KEM-OTP Feasibility Pilot on {KEM_ALG}...")
    
    # 1. Check Entropy Speed
    entropy_speed = check_entropy_speed()
    
    # 2. Check Latency
    avg_lat, p99_lat = benchmark_latency()
    
    # 3. Check Throughput & CPU
    otp_throughput, cpu_usage = benchmark_throughput()
    
    # 4. Save
    save_report(entropy_speed, avg_lat, otp_throughput, cpu_usage)
    
    # 5. Final Feasibility Check 
    print_header("FINAL VERDICT")
    
    # Define thresholds
    TARGET_THROUGHPUT = 2.5 # KB/s (Control Workload)
    
    if otp_throughput > TARGET_THROUGHPUT:
        margin = otp_throughput / TARGET_THROUGHPUT
        print(f"RESULT: PASS (Feasible)")
        print(f"You have a {margin:.1f}x safety margin over 'Control' workload requirements.")
    else:
        print("RESULT: FAIL (Too Slow)")

if __name__ == "__main__":
    main()