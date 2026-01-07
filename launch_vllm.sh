#!/bin/bash
# =============================================================================
# vLLM Server Launcher - Optimized for 2x NVIDIA L40S (48GB each)
# =============================================================================

set -e

# Configuration
MODEL="${MODEL:-mistralai/Mistral-7B-Instruct-v0.3}"
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
# Slightly reduced utilization to leave room for KV cache on full utilization
GPU_MEMORY_UTILIZATION="${GPU_MEM:-0.95}"

# Model presets for 2x L40S (96GB total VRAM)
declare -A MODEL_CONFIGS=(
    # [model_name]="tensor_parallel_size max_model_len"

    # --- Standard Models ---
    ["mistralai/Mistral-7B-Instruct-v0.3"]="1 32768"
    ["codellama/CodeLlama-13b-Instruct-hf"]="1 16384"
    ["meta-llama/Llama-3.1-70B-Instruct"]="2 8192"
    ["Qwen/Qwen2.5-72B-Instruct"]="2 8192"

    # --- FIXED: NVIDIA Nemotron 3 Nano ---
    # Correct HF ID: nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16
    # Weights ~60GB (BF16). Requires TP=2 on L40S.
    ["nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16"]="2 16384"

    # --- NEW: Qwen 3 Coder ---
    # Qwen 3 Coder 30B (A3B MoE). Weights ~62GB.
    ["Qwen/Qwen3-Coder-30B-A3B-Instruct"]="2 32768"

    # --- NEW: Google Gemma 3 ---
    # Gemma 3 27B. Weights ~54GB. Fits comfortably on 2 GPUs.
    ["google/gemma-3-27b-it"]="2 65536"

    # --- Legacy/Specialty ---
    ["openai/gpt-oss-120b"]="2 8192"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --model|-m)
            MODEL="$2"
            shift 2
            ;;
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        # Shortcuts
        --nemotron)
            # Fixed identifier
            MODEL="nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16"
            shift
            ;;
        --qwen-coder)
            MODEL="Qwen/Qwen3-Coder-30B-A3B-Instruct"
            shift
            ;;
        --gemma)
            MODEL="google/gemma-3-27b-it"
            shift
            ;;
        --gpt-oss)
            MODEL="openai/gpt-oss-120b"
            shift
            ;;
        --70b)
            MODEL="meta-llama/Llama-3.1-70B-Instruct"
            shift
            ;;
        --mistral)
            MODEL="mistralai/Mistral-7B-Instruct-v0.3"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --model, -m MODEL    Model to serve"
            echo "  --port, -p PORT      Port to serve on (default: 8000)"
            echo "  --nemotron           Use NVIDIA Nemotron 3 Nano 30B (Fixed ID)"
            echo "  --qwen-coder         Use Qwen 3 Coder 30B"
            echo "  --gemma              Use Gemma 3 27B"
            echo "  --70b                Use Llama 3.1 70B"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get model config
if [[ -v MODEL_CONFIGS[$MODEL] ]]; then
    read -r TP_SIZE MAX_LEN <<< "${MODEL_CONFIGS[$MODEL]}"
else
    echo "Warning: Unknown model '$MODEL', using defaults (TP=1)"
    TP_SIZE=1
    MAX_LEN=4096
fi

echo "=============================================="
echo "vLLM Server Launcher for 2x L40S"
echo "=============================================="
echo "Model: $MODEL"
echo "Tensor Parallel Size: $TP_SIZE"
echo "Max Model Length: $MAX_LEN"
echo "=============================================="

# Check CUDA availability
if ! command -v nvidia-smi &> /dev/null; then
    echo "Error: nvidia-smi not found."
    exit 1
fi

export CUDA_VISIBLE_DEVICES=0,1

# Launch vLLM
# Note: trust-remote-code is crucial for newer models like Nemotron/Qwen3
echo "Starting vLLM server..."
uv run python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL" \
    --tensor-parallel-size "$TP_SIZE" \
    --max-model-len "$MAX_LEN" \
    --gpu-memory-utilization "$GPU_MEMORY_UTILIZATION" \
    --host "$HOST" \
    --port "$PORT" \
    --dtype auto \
    --max-num-seqs 256 \
    --disable-log-requests \
    --trust-remote-code \
    --enforce-eager \
    2>&1 | tee vllm_server.log &

VLLM_PID=$!
echo "vLLM PID: $VLLM_PID"

# Wait for server
echo "Waiting for server to be ready..."
for i in {1..300}; do
    if curl -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
        echo ""
        echo "✓ vLLM server is ready at http://localhost:$PORT"
        echo "Using model: $MODEL"
        echo "PID: $VLLM_PID"
        echo "$VLLM_PID" > /tmp/vllm_server.pid
        wait $VLLM_PID
        exit 0
    fi
    echo -n "."
    sleep 2
done

echo "\nError: Server failed to start. Check vllm_server.log"
kill $VLLM_PID 2>/dev/null
exit 1