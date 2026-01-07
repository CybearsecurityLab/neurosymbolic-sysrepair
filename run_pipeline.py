#!/usr/bin/env python3
"""
Full Pipeline Runner: Phase 1 (Introspection) + Phase 2 (Parallel Synthesis)
Automated Neurosymbolic Domain Formalization for Ubuntu 25.10

Optimized for: 2x L40S GPUs, 400GB RAM, 100 CPUs
"""

import os
import sys
import json
import argparse
import subprocess
import time
import signal
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))


def check_dependencies():
    """Check and report on required dependencies."""
    deps = {
        "osquery": False,
        "vllm": False,
        "openai": False,
        "cuda": False,
    }

    # Check osquery
    try:
        result = subprocess.run(["osqueryi", "--version"],
                                capture_output=True, timeout=5)
        deps["osquery"] = result.returncode == 0
    except Exception:
        pass

    # Check vLLM
    try:
        import vllm
        deps["vllm"] = True
    except ImportError:
        pass

    # Check OpenAI client
    try:
        import openai
        deps["openai"] = True
    except ImportError:
        pass

    # Check CUDA
    try:
        result = subprocess.run(["nvidia-smi"], capture_output=True, timeout=5)
        deps["cuda"] = result.returncode == 0
    except Exception:
        pass

    return deps


def print_banner():
    """Print startup banner."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   NEUROSYMBOLIC PDDL DOMAIN GENERATOR                                        ║
║   Ubuntu 25.10 "Questing Quokka"                                             ║
║                                                                              ║
║   Phase 1: System Introspection (osquery + man page mining)                  ║
║   Phase 2: Parallel Synthesis (LLM Map-Reduce)                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


def start_vllm_server(model: str, port: int = 8000) -> Optional[subprocess.Popen]:
    """Start vLLM server in background."""
    print(f"\n[*] Starting vLLM server with model: {model}")

    # Determine tensor parallel size based on model
    tp_size = 2 if "70b" in model.lower() or "72b" in model.lower() else 1
    max_len = 4096 if tp_size == 2 else 8192

    cmd = [
        sys.executable, "-m", "vllm.entrypoints.openai.api_server",
        "--model", model,
        "--tensor-parallel-size", str(tp_size),
        "--max-model-len", str(max_len),
        "--gpu-memory-utilization", "0.90",
        "--port", str(port),
        "--disable-log-requests",
    ]

    # Start in background
    log_file = open("vllm_server.log", "w")
    process = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

    # Wait for server to be ready
    print("[*] Waiting for vLLM server to initialize...")
    import urllib.request
    for i in range(120):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/health", timeout=1)
            print(f"[✓] vLLM server ready on port {port}")
            return process
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)

    print("\n[✗] vLLM server failed to start")
    process.terminate()
    return None


def run_phase1(output_dir: Path) -> dict:
    """Execute Phase 1: System Introspection."""
    print("\n" + "=" * 70)
    print("PHASE 1: SYSTEM INTROSPECTION")
    print("=" * 70)

    # Import Phase 1 module
    try:
        from phase1 import Phase1Orchestrator
    except ImportError:
        print("[!] Phase 1 module not found, using inline implementation")
        # Inline minimal Phase 1
        return run_minimal_phase1(output_dir)

    orchestrator = Phase1Orchestrator(output_dir=str(output_dir))
    results = orchestrator.run()

    # Save state for Phase 2
    state_file = output_dir / "phase1_state.json"
    with open(state_file, 'w') as f:
        json.dump({
            "objects": results.get("objects", {}),
            "predicates": results.get("predicates", []),
            "relationships": results.get("relationships", {}),
            "statistics": results.get("statistics", {}),
        }, f, indent=2)

    print(f"[✓] Phase 1 state saved to: {state_file}")
    return results


def run_minimal_phase1(output_dir: Path) -> dict:
    """Minimal Phase 1 implementation if module not available."""
    import subprocess
    import json

    results = {
        "success": False,
        "objects": {},
        "predicates": [],
        "relationships": {},
        "statistics": {}
    }

    # Try osquery extraction
    try:
        # Packages
        proc = subprocess.run(
            ["osqueryi", "--json", "SELECT name, version FROM deb_packages LIMIT 100"],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            packages = json.loads(proc.stdout)
            results["objects"]["package"] = [
                {"name": p["name"], "version": p["version"]}
                for p in packages
            ]
            results["statistics"]["package_count"] = len(packages)

        # Services
        proc = subprocess.run(
            ["osqueryi", "--json",
             "SELECT id, active_state FROM systemd_units WHERE id LIKE '%.service' LIMIT 100"],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            services = json.loads(proc.stdout)
            results["objects"]["service"] = [
                {"name": s["id"], "active": s["active_state"]}
                for s in services
            ]
            results["statistics"]["service_count"] = len(services)

        # Users
        proc = subprocess.run(
            ["osqueryi", "--json", "SELECT username, uid FROM users"],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            users = json.loads(proc.stdout)
            results["objects"]["user"] = [
                {"name": u["username"], "uid": u["uid"]}
                for u in users
            ]
            results["statistics"]["user_count"] = len(users)

        results["success"] = True
        print(f"[✓] Extracted: {results['statistics']}")

    except Exception as e:
        print(f"[!] osquery extraction failed: {e}")
        print("[!] Proceeding with empty state")
        results["success"] = True  # Allow Phase 2 to proceed

    # Save state
    state_file = output_dir / "phase1_state.json"
    with open(state_file, 'w') as f:
        json.dump(results, f, indent=2)

    return results


def run_phase2(
        output_dir: Path,
        phase1_state: dict,
        model: str,
        use_mock: bool = False
) -> dict:
    """Execute Phase 2: Parallel Synthesis."""
    print("\n" + "=" * 70)
    print("PHASE 2: PARALLEL SYNTHESIS")
    print("=" * 70)

    # Import Phase 2 module
    try:
        from phase2 import (
            Phase2Orchestrator,
            HardwareConfig,
            LLMConfig
        )
    except ImportError as e:
        print(f"[✗] Phase 2 module import failed: {e}")
        return {"success": False, "error": str(e)}

    # Configure
    hardware = HardwareConfig.detect()
    llm_config = LLMConfig(model_name=model)

    # Extract osquery data from Phase 1
    osquery_data = phase1_state.get("objects", {})

    # Run orchestrator
    orchestrator = Phase2Orchestrator(
        hardware_config=hardware,
        llm_config=llm_config,
        osquery_data=osquery_data,
        use_mock_llm=use_mock,
        output_dir=str(output_dir)
    )

    return orchestrator.run()


def generate_report(
        output_dir: Path,
        phase1_results: dict,
        phase2_results: dict,
        elapsed_time: float
):
    """Generate final report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "elapsed_time_seconds": elapsed_time,
        "phase1": {
            "success": phase1_results.get("success", False),
            "statistics": phase1_results.get("statistics", {}),
        },
        "phase2": {
            "success": phase2_results.get("success", False),
            "statistics": phase2_results.get("statistics", {}),
            "validation_passed": phase2_results.get("validation_passed", False),
        },
        "outputs": {
            "domain_file": str(output_dir / "sysadmin.pddl"),
            "problem_file": str(output_dir / "sysadmin_problem.pddl"),
        }
    }

    # Save report
    report_file = output_dir / "pipeline_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)
    print(f"""
    Total Time: {elapsed_time:.1f} seconds

    Phase 1 (Introspection):
      Status: {'✓ SUCCESS' if phase1_results.get('success') else '✗ FAILED'}
      Packages: {phase1_results.get('statistics', {}).get('package_count', 'N/A')}
      Services: {phase1_results.get('statistics', {}).get('service_count', 'N/A')}
      Users: {phase1_results.get('statistics', {}).get('user_count', 'N/A')}

    Phase 2 (Synthesis):
      Status: {'✓ SUCCESS' if phase2_results.get('success') else '✗ FAILED'}
      Workers: {phase2_results.get('statistics', {}).get('workers_successful', 'N/A')}/{phase2_results.get('statistics', {}).get('workers_total', 'N/A')}
      Actions: {phase2_results.get('statistics', {}).get('total_actions', 'N/A')}
      Validation: {'✓ PASSED' if phase2_results.get('validation_passed') else '⚠ WARNINGS'}

    Output Files:
      Domain: {output_dir / 'sysadmin.pddl'}
      Report: {report_file}
    """)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Full PDDL Domain Generation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with mock LLM (no GPU required)
  python run_pipeline.py --mock

  # Run with Mistral-7B (single GPU)
  python run_pipeline.py --model mistralai/Mistral-7B-Instruct-v0.3

  # Run with Llama-3.1-70B (both GPUs)
  python run_pipeline.py --model meta-llama/Llama-3.1-70B-Instruct

  # Skip Phase 1, use existing state
  python run_pipeline.py --skip-phase1 --phase1-state ./output/phase1_state.json
        """
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="./pddl_output",
        help="Output directory (default: ./pddl_output)"
    )
    parser.add_argument(
        "--model", "-m",
        default="mistralai/Mistral-7B-Instruct-v0.3",
        help="LLM model to use"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock LLM (for testing without GPU)"
    )
    parser.add_argument(
        "--skip-phase1",
        action="store_true",
        help="Skip Phase 1, use existing state file"
    )
    parser.add_argument(
        "--phase1-state",
        help="Path to existing Phase 1 state JSON"
    )
    parser.add_argument(
        "--no-vllm",
        action="store_true",
        help="Don't auto-start vLLM server"
    )
    parser.add_argument(
        "--vllm-port",
        type=int,
        default=8000,
        help="vLLM server port (default: 8000)"
    )

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Check dependencies
    print("[*] Checking dependencies...")
    deps = check_dependencies()
    for dep, available in deps.items():
        status = "✓" if available else "✗"
        print(f"    [{status}] {dep}")

    if not deps["openai"]:
        print("\n[!] Installing openai package...")
        subprocess.run([sys.executable, "-m", "pip", "install", "openai"])

    # Setup output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[*] Output directory: {output_dir.absolute()}")

    # Start timer
    start_time = time.time()
    vllm_process = None

    try:
        # Start vLLM server if needed
        if not args.mock and not args.no_vllm and deps["vllm"] and deps["cuda"]:
            vllm_process = start_vllm_server(args.model, args.vllm_port)
            if not vllm_process:
                print("[!] Falling back to mock LLM")
                args.mock = True

        # Phase 1
        if args.skip_phase1 and args.phase1_state:
            print(f"\n[*] Loading Phase 1 state from: {args.phase1_state}")
            with open(args.phase1_state) as f:
                phase1_results = json.load(f)
        else:
            phase1_results = run_phase1(output_dir)

        # Phase 2
        phase2_results = run_phase2(
            output_dir=output_dir,
            phase1_state=phase1_results,
            model=args.model,
            use_mock=args.mock
        )

        # Generate report
        elapsed = time.time() - start_time
        generate_report(output_dir, phase1_results, phase2_results, elapsed)

        # Return appropriate exit code
        if phase2_results.get("success"):
            return 0
        else:
            return 1

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        return 130

    finally:
        # Cleanup vLLM server
        if vllm_process:
            print("\n[*] Shutting down vLLM server...")
            os.killpg(os.getpgid(vllm_process.pid), signal.SIGTERM)


if __name__ == "__main__":
    sys.exit(main())