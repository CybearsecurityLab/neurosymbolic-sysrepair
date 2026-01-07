#!/bin/bash
# =============================================================================
# vLLM Server Launcher - Optimized for 2x NVIDIA L40S (48GB each)
# =============================================================================

set -e

# Configuration
MODEL="${MODEL:-mistralai/Mistral-7B-Instruct-v0.3}"
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
GPU_MEMORY_UTILIZATION="${GPU_MEM:-0.90}"

# Model presets for 2x L40S (96GB total VRAM)
declare -A MODEL_CONFIGS=(
    # [model_name]="tensor_parallel_size max_model_len"
    ["mistralai/Mistral-7B-Instruct-v0.3"]="1 8192"
    ["codellama/CodeLlama-13b-Instruct-hf"]="1 8192"
    ["meta-llama/Llama-3.1-70B-Instruct"]="2 4096"
    ["Qwen/Qwen2.5-72B-Instruct"]="2 4096"
    ["deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"]="1 8192"
    ["microsoft/Phi-3-medium-128k-instruct"]="1 16384"
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
        --70b)
            MODEL="meta-llama/Llama-3.1-70B-Instruct"
            shift
            ;;
        --mistral)
            MODEL="mistralai/Mistral-7B-Instruct-v0.3"
            shift
            ;;
        --codellama)
            MODEL="codellama/CodeLlama-13b-Instruct-hf"
            shift
            ;;
        --qwen)
            MODEL="Qwen/Qwen2.5-72B-Instruct"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --model, -m MODEL   Model to serve (default: Mistral-7B)"
            echo "  --port, -p PORT     Port to serve on (default: 8000)"
            echo "  --70b               Use Llama-3.1-70B (requires both GPUs)"
            echo "  --mistral           Use Mistral-7B-Instruct"
            echo "  --codellama         Use CodeLlama-13B"
            echo "  --qwen              Use Qwen2.5-72B"
            echo ""
            echo "Supported models for 2x L40S:"
            for model in "${!MODEL_CONFIGS[@]}"; do
                echo "  - $model"
            done
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
    echo "Warning: Unknown model, using defaults"
    TP_SIZE=1
    MAX_LEN=8192
fi

echo "=============================================="
echo "vLLM Server Launcher for 2x L40S"
echo "=============================================="
echo "Model: $MODEL"
echo "Tensor Parallel Size: $TP_SIZE"
echo "Max Model Length: $MAX_LEN"
echo "GPU Memory Utilization: $GPU_MEMORY_UTILIZATION"
echo "Port: $PORT"
echo "=============================================="

# Check CUDA availability
if ! command -v nvidia-smi &> /dev/null; then
    echo "Error: nvidia-smi not found. CUDA drivers not installed?"
    exit 1
fi

echo ""
echo "GPU Status:"
nvidia-smi --query-gpu=index,name,memory.total,memory.free --format=csv
echo ""

# Set CUDA visible devices
export CUDA_VISIBLE_DEVICES=0,1

# Launch vLLM with optimized settings
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
    --max-num-batched-tokens 8192 \
    --disable-log-requests \
    --trust-remote-code \
    2>&1 | tee vllm_server.log &

VLLM_PID=$!
echo "vLLM PID: $VLLM_PID"

# Wait for server to be ready
echo "Waiting for server to be ready..."
for i in {1..120}; do
    if curl -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
        echo ""
        echo "✓ vLLM server is ready at http://localhost:$PORT"
        echo ""
        echo "API Endpoints:"
        echo "  - Health: http://localhost:$PORT/health"
        echo "  - Models: http://localhost:$PORT/v1/models"
        echo "  - Completions: http://localhost:$PORT/v1/chat/completions"
        echo ""
        echo "To stop: kill $VLLM_PID"
        echo ""

        # Save PID for later
        echo "$VLLM_PID" > /tmp/vllm_server.pid

        # Wait for server process
        wait $VLLM_PID
        exit 0
    fi
    echo -n "."
    sleep 1
done

echo ""
echo "Error: Server failed to start within 120 seconds"
echo "Check vllm_server.log for details"
kill $VLLM_PID 2>/dev/null
exit 1