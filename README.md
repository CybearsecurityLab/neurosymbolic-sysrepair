# Auto-Sysrepair

## Commands

### Setup

```bash
sudo bash scripts/setup.sh
```

### Phase 1: System Introspection

```bash
python -m phase1.main \
  --output-dir ./pddl_output/phase1 \
  --llm-model gemma-4-31b \
  --llm-url http://10.100.203.130:8001/v1 \
  --scoping dynamic
```

### Phase 2: Parallel Synthesis

```bash
python -m phase2.main \
  --output-dir ./pddl_output/phase2 \
  --phase1-state ./pddl_output/phase1/phase1_statep2.json \
  --model gemma-4-31b \
  --base-url http://10.100.203.130:8001/v1
```

### Phase 3: Iterative Refinement

```bash
python -m phase3.main \
  --domain ./pddl_output/phase2/sysadmin.pddl \
  --problem ./pddl_output/phase2/sysadmin_problem.pddl \
  --output-dir ./pddl_output/phase3 \
  --target-score 0.9 \
  --max-iterations 10 \
  --llm-model gemma-4-31b \
  --llm-url http://10.100.203.130:8001/v1
```

### Full Pipeline (Phase 1 + 2 + 3)

```bash
python run_pipeline.py \
  --output-dir ./pddl_output \
  --model gemma-4-31b
```
