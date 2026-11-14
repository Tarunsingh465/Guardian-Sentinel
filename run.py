"""
Guardian-Sentinel Master CLI Launcher
Convenient command-line interface to launch API, Streamlit SOC Dashboard, or run Research suites.
"""

import sys
import subprocess
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def run_api():
    print("🚀 Launching Guardian-Sentinel FastAPI Backend on http://127.0.0.1:8000 ...")
    cmd = [sys.executable, "-m", "uvicorn", "guardian.api.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
    subprocess.run(cmd, cwd=BASE_DIR)

def run_dashboard():
    print("🛡️ Launching Guardian-Sentinel Streamlit SOC Console on http://localhost:8501 ...")
    cmd = [sys.executable, "-m", "streamlit", "run", "guardian/dashboard/app.py", "--server.port", "8501"]
    subprocess.run(cmd, cwd=BASE_DIR)

def run_research():
    print("🔬 Executing Guardian-Sentinel Senior Data Science Research Suite...")
    from research.statistical_testing import run_hypothesis_suite
    from research.eda_engine import run_advanced_eda_profile
    from research.imbalance_benchmark import run_class_imbalance_benchmark
    import json

    print("\n--- 1. STATISTICAL HYPOTHESIS TESTING ---")
    hyp = run_hypothesis_suite()
    print(json.dumps(hyp, indent=2))

    print("\n--- 2. CLASS IMBALANCE BENCHMARK ---")
    imb = run_class_imbalance_benchmark()
    print(json.dumps(imb["benchmark_table"], indent=2))

    print("\n--- 3. ADVANCED EDA SUMMARY ---")
    eda = run_advanced_eda_profile()
    print(f"Total Features Analyzed: {eda['total_raw_features']}")
    print(f"Collinear Feature Pairs Identified: {len(eda['collinear_pairs'])}")
    print("\n✅ All Research Modules Executed Successfully! Full reports available in /reports directory.")

def main():
    parser = argparse.ArgumentParser(description="Guardian-Sentinel Master Launcher")
    parser.add_argument("--api", action="store_true", help="Launch FastAPI REST Microservice")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit SOC Dashboard")
    parser.add_argument("--research", action="store_true", help="Execute Senior Data Science Hypothesis & EDA Suite")
    parser.add_argument("--all", action="store_true", help="Launch API and Dashboard concurrently")

    args = parser.parse_args()

    if args.api:
        run_api()
    elif args.dashboard:
        run_dashboard()
    elif args.research:
        run_research()
    elif args.all:
        import threading
        t = threading.Thread(target=run_api, daemon=True)
        t.start()
        run_dashboard()
    else:
        parser.print_help()
        print("\nQuick Start Examples:")
        print("  python run.py --dashboard   # Start the Streamlit SOC & Research Console")
        print("  python run.py --api         # Start the FastAPI REST Microservice")
        print("  python run.py --research    # Run statistical hypothesis tests & EDA benchmarks")
        print("  python run.py --all         # Launch both API and Dashboard")

if __name__ == "__main__":
    main()
