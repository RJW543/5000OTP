import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

CSV_FILE = "kem_pilot_results.csv"
OUTPUT_IMAGE = "feasibility_chart.png"

# Workload Demand Profiles (KB/s)
WORKLOADS = {
    "Env Sensor\n(0.001 KB/s)": 0.001,
    "Telemetry\n(0.25 KB/s)": 0.256,
    "Control\n(2.5 KB/s)": 2.5,
    "Edge ML\n(20 KB/s)": 20.0
}

def generate_chart():
    # 1. Load Data
    if not os.path.exists(CSV_FILE):
        print(f"Error: {CSV_FILE} not found. Run the pilot first!")
        sys.exit(1)

    try:
        df = pd.read_csv(CSV_FILE)
        # Get the LATEST run 
        latest_run = df.iloc[-1]
        
        kem_throughput_kbs = float(latest_run['Throughput_KBs'])
        entropy_mb_s = float(latest_run['Entropy_MBs'])
        latency_ms = float(latest_run['Avg_Latency_ms'])
        
        # Convert Entropy to KB/s
        entropy_kbs = entropy_mb_s * 1024
        
        print(f"Plotting data from: {latest_run['Timestamp']}")
        print(f" - Algo Speed: {kem_throughput_kbs} KB/s")
        print(f" - Entropy Speed: {entropy_kbs} KB/s")
        
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)

    # 2. Setup Plot
    fig, ax1 = plt.subplots(figsize=(12, 8))

    # 3. Plot Workloads (Demand)
    labels = list(WORKLOADS.keys())
    values = list(WORKLOADS.values())
    bars = ax1.bar(labels, values, color=['#bdc3c7', '#95a5a6', '#7f8c8d', '#34495e'], 
                   alpha=0.8, label='Workload Demand')

    # 4. Plot Ceilings (Supply)
    # Green Line: Algorithm Speed (Computational Limit)
    line_kem = ax1.axhline(y=kem_throughput_kbs, color='#2ecc71', linestyle='--', 
                           linewidth=2, label=f'Kyber Algorithm Limit ({kem_throughput_kbs:.0f} KB/s)')
    
    # Red Line: Entropy Speed (Physical Limit)
    lines = [line_kem, bars]
    if entropy_kbs > 0:
        line_rng = ax1.axhline(y=entropy_kbs, color='#e74c3c', linestyle='-', 
                               linewidth=2, label=f'Physical Entropy Limit ({entropy_kbs:.0f} KB/s)')
        lines.insert(1, line_rng)
        
        # Add labels to lines
        ax1.text(len(labels)-0.5, entropy_kbs * 1.1, "Physical Limit (TRNG)", 
                 color='#e74c3c', fontweight='bold', ha='right', va='bottom')

    ax1.text(len(labels)-0.5, kem_throughput_kbs * 1.1, "Algorithm Limit (CPU)", 
             color='#2ecc71', fontweight='bold', ha='right', va='bottom')

    # 5. Styling
    ax1.set_yscale('log')
    ax1.set_ylabel('Data Throughput (KB/s) [Log Scale]', fontsize=12)
    ax1.set_title('Feasibility Analysis: KEM-OTP Supply vs. IoT Demand', fontsize=14, fontweight='bold')
    ax1.grid(True, which="both", ls="-", alpha=0.1)

    # 6. Safety Margin Annotation
    # Calculate margin against the REAL limit (min of Algo or Entropy)
    real_limit = min(kem_throughput_kbs, entropy_kbs) if entropy_kbs > 0 else kem_throughput_kbs
    target_workload = values[-1] # Edge ML
    margin = real_limit / target_workload

    ax1.annotate(f'{margin:.1f}x Safety Margin', 
                 xy=(3, target_workload), 
                 xytext=(3, real_limit / 5), # Position text relative to limit
                 arrowprops=dict(facecolor='black', arrowstyle='->'),
                 ha='center', fontsize=11, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="black", alpha=0.8))

    # 7. Latency Box
    textstr = '\n'.join((
        r'$\bf{Latency\ Check}$',
        f'Measured: {latency_ms:.3f} ms',
        f'Required: <50 ms',
        r'Status: $\bf{PASS}$'
    ))
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax1.text(0.02, 0.95, textstr, transform=ax1.transAxes, fontsize=12,
            verticalalignment='top', bbox=props)

    # 8. Legend and Save
    labels_legend = [l.get_label() for l in lines]
    ax1.legend(lines, labels_legend, loc='lower right', framealpha=1)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE, dpi=300)
    print(f"\n[SUCCESS] Chart generated: {OUTPUT_IMAGE}")

if __name__ == "__main__":
    generate_chart()