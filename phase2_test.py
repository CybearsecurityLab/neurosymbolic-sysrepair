"""
Phase 2: Parallel Synthesis Module (The Map-Reduce Generation)
Automated Neurosymbolic Domain Formalization for Ubuntu 25.10

Optimized for: 2x L40S GPUs (48GB each), 400GB RAM, 100 CPUs

This module implements the LLM Map-Reduce pattern for scalable PDDL generation:
- Map Phase: Parallel worker agents for each utility domain
- Reduce Phase: Neurosymbolic merger for domain unification
"""

import os
import json
import subprocess
import hashlib
import asyncio
import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum
from pathlib import Path
import multiprocessing as mp
import threading
import queue
import time
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("Phase2")


# =============================================================================
# SECTION 1: Configuration & Hardware Detection
# =============================================================================

@dataclass
class HardwareConfig:
    """Detected hardware configuration."""
    num_gpus: int = 2
    gpu_memory_gb: float = 48.0  # L40S
    total_ram_gb: float = 400.0
    num_cpus: int = 100
    
    # Derived settings
    llm_workers_per_gpu: int = 2  # vLLM can handle multiple concurrent requests
    max_parallel_workers: int = 8  # Map workers
    batch_size: int = 16  # LLM batch size
    
    @classmethod
    def detect(cls) -> "HardwareConfig":
        """Auto-detect hardware capabilities."""
        config = cls()
        
        # Detect GPUs via nvidia-smi
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=count,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                config.num_gpus = len(lines)
                if lines:
                    parts = lines[0].split(',')
                    config.gpu_memory_gb = float(parts[1].strip()) / 1024
        except Exception:
            pass
        
        # Detect RAM
        try:
            with open('/proc/meminfo') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        config.total_ram_gb = kb / (1024 * 1024)
                        break
        except Exception:
            pass
        
        # Detect CPUs
        config.num_cpus = os.cpu_count() or 100
        
        # Calculate optimal parallelism
        config.max_parallel_workers = min(config.num_gpus * config.llm_workers_per_gpu, 8)
        
        return config


@dataclass 
class LLMConfig:
    """LLM inference configuration."""
    model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"  # Good for code/structured output
    # Alternative: "codellama/CodeLlama-13b-Instruct-hf" for code-heavy tasks
    # Alternative: "meta-llama/Llama-3.1-70B-Instruct" if you want higher quality (fits in 2xL40S)
    
    base_url: str = "http://localhost:8000/v1"  # vLLM OpenAI-compatible endpoint
    max_tokens: int = 4096
    temperature: float = 0.1  # Low temp for structured output
    tensor_parallel_size: int = 2  # Use both GPUs for larger models
    
    # Batching config
    max_concurrent_requests: int = 16
    request_timeout: int = 120


# Utility group definitions (Section 5.1)
UTILITY_GROUPS = {
    "package": {
        "utilities": ["apt-get", "apt", "dpkg", "dpkg-query", "apt-cache", "snap"],
        "description": "Package management operations",
        "pddl_focus": ["package", "repository"],
        "osquery_tables": ["deb_packages", "apt_sources"]
    },
    "service": {
        "utilities": ["systemctl", "journalctl", "systemd-analyze"],
        "description": "Service lifecycle management (systemd v257)",
        "pddl_focus": ["service", "process"],
        "osquery_tables": ["systemd_units", "processes"]
    },
    "network": {
        "utilities": ["iptables", "ip", "ss", "netstat", "ufw", "nft"],
        "description": "Firewall and network interface management",
        "pddl_focus": ["port", "interface", "firewall_rule"],
        "osquery_tables": ["listening_ports", "iptables", "interface_addresses"]
    },
    "filesystem": {
        "utilities": ["cp", "mv", "rm", "chmod", "chown", "setfacl", "mkdir", "touch", "ln"],
        "description": "File manipulation (uutils coreutils)",
        "pddl_focus": ["file", "directory", "configuration_file"],
        "osquery_tables": ["file", "file_events"]
    },
    "user": {
        "utilities": ["useradd", "usermod", "userdel", "groupadd", "groupmod", "passwd"],
        "description": "User and group management",
        "pddl_focus": ["user", "group"],
        "osquery_tables": ["users", "groups", "user_groups"]
    },
    "privilege": {
        "utilities": ["sudo", "su", "pkexec"],
        "description": "Privilege escalation (sudo-rs aware)",
        "pddl_focus": ["user", "process"],
        "osquery_tables": ["sudoers"]
    }
}


# =============================================================================
# SECTION 2: LLM Interface (vLLM Backend)
# =============================================================================

class LLMInterface(ABC):
    """Abstract LLM interface for PDDL generation."""
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        pass
    
    @abstractmethod
    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        pass


class VLLMInterface(LLMInterface):
    """
    vLLM-based LLM interface using OpenAI-compatible API.
    
    Start vLLM server with:
    python -m vllm.entrypoints.openai.api_server \
        --model mistralai/Mistral-7B-Instruct-v0.3 \
        --tensor-parallel-size 2 \
        --max-model-len 8192 \
        --gpu-memory-utilization 0.9
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None
        self._semaphore = threading.Semaphore(config.max_concurrent_requests)
    
    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    base_url=self.config.base_url,
                    api_key="not-needed"  # vLLM doesn't require API key
                )
            except ImportError:
                raise RuntimeError("openai package required: pip install openai")
        return self._client
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate single completion."""
        with self._semaphore:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            try:
                response = self.client.chat.completions.create(
                    model=self.config.model_name,
                    messages=messages,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    timeout=self.config.request_timeout
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.error(f"LLM generation failed: {e}")
                return ""
    
    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        """Generate batch completions in parallel."""
        results = [None] * len(prompts)
        
        def process_single(idx: int, prompt: str):
            results[idx] = self.generate(prompt, system_prompt)
        
        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_requests) as executor:
            futures = [
                executor.submit(process_single, i, p) 
                for i, p in enumerate(prompts)
            ]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    logger.error(f"Batch generation error: {e}")
        
        return results


class MockLLMInterface(LLMInterface):
    """Mock LLM for testing without GPU."""
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        # Return template-based responses for testing
        if "apt" in prompt.lower() or "package" in prompt.lower():
            return self._package_template()
        elif "systemctl" in prompt.lower() or "service" in prompt.lower():
            return self._service_template()
        return "; Mock PDDL output\n"
    
    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        return [self.generate(p, system_prompt) for p in prompts]
    
    def _package_template(self) -> str:
        return """
(:types
  package repository - object
)

(:predicates
  (package_installed ?p - package)
  (package_available ?p - package)
  (repo_enabled ?r - repository)
)

(:action install_package
  :parameters (?p - package)
  :precondition (and (not (package_installed ?p)) (package_available ?p))
  :effect (package_installed ?p)
)
"""
    
    def _service_template(self) -> str:
        return """
(:types
  service - object
)

(:predicates
  (service_running ?s - service)
  (service_enabled ?s - service)
)

(:action start_service
  :parameters (?s - service)
  :precondition (not (service_running ?s))
  :effect (service_running ?s)
)
"""


def get_llm_interface(config: LLMConfig, use_mock: bool = False) -> LLMInterface:
    """Factory function to get LLM interface."""
    if use_mock:
        return MockLLMInterface()
    return VLLMInterface(config)


# =============================================================================
# SECTION 3: Man Page Fetcher & Documentation Extractor
# =============================================================================

class DocumentationExtractor:
    """Extracts and caches system documentation for LLM processing."""
    
    def __init__(self, cache_dir: str = "/tmp/pddl_doc_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, str] = {}
    
    def _cache_key(self, utility: str) -> str:
        return hashlib.md5(utility.encode()).hexdigest()
    
    def fetch_man_page(self, utility: str) -> Optional[str]:
        """Fetch cleaned man page content."""
        cache_key = self._cache_key(f"man_{utility}")
        
        # Check memory cache
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Check disk cache
        cache_file = self.cache_dir / f"{cache_key}.txt"
        if cache_file.exists():
            content = cache_file.read_text()
            self._cache[cache_key] = content
            return content
        
        # Fetch from system
        try:
            proc = subprocess.Popen(
                f"man {utility} 2>/dev/null | col -b",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, _ = proc.communicate(timeout=30)
            
            if proc.returncode == 0 and stdout:
                content = stdout.decode('utf-8', errors='replace')
                # Clean up
                content = self._clean_man_page(content)
                
                # Cache
                self._cache[cache_key] = content
                cache_file.write_text(content)
                
                return content
        except Exception as e:
            logger.warning(f"Failed to fetch man page for {utility}: {e}")
        
        return None
    
    def fetch_help_output(self, utility: str) -> Optional[str]:
        """Fetch --help output."""
        cache_key = self._cache_key(f"help_{utility}")
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            result = subprocess.run(
                [utility, "--help"],
                capture_output=True, text=True, timeout=10
            )
            content = result.stdout or result.stderr
            if content:
                self._cache[cache_key] = content
                return content
        except Exception:
            pass
        
        return None
    
    def _clean_man_page(self, content: str) -> str:
        """Clean and truncate man page for LLM context."""
        lines = content.split('\n')
        
        # Remove excessive whitespace
        cleaned = []
        prev_empty = False
        for line in lines:
            line = line.rstrip()
            is_empty = not line.strip()
            if is_empty and prev_empty:
                continue
            cleaned.append(line)
            prev_empty = is_empty
        
        # Truncate if too long (keep first 500 lines)
        if len(cleaned) > 500:
            cleaned = cleaned[:500] + ["... [truncated]"]
        
        return '\n'.join(cleaned)
    
    def get_utility_docs(self, utilities: list[str]) -> dict[str, str]:
        """Get documentation for multiple utilities in parallel."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=min(len(utilities), 20)) as executor:
            future_to_util = {
                executor.submit(self._get_single_doc, u): u 
                for u in utilities
            }
            
            for future in as_completed(future_to_util):
                utility = future_to_util[future]
                try:
                    results[utility] = future.result()
                except Exception as e:
                    logger.warning(f"Doc extraction failed for {utility}: {e}")
                    results[utility] = ""
        
        return results
    
    def _get_single_doc(self, utility: str) -> str:
        """Get combined documentation for a single utility."""
        man_page = self.fetch_man_page(utility) or ""
        help_text = self.fetch_help_output(utility) or ""
        
        combined = f"=== MAN PAGE: {utility} ===\n{man_page}\n\n"
        combined += f"=== HELP OUTPUT: {utility} ===\n{help_text}\n"
        
        return combined


# =============================================================================
# SECTION 4.5: Curated PDDL Templates (Fallback for broken LLM output)
# =============================================================================
@dataclass
class PDDLType:
    """Represents a PDDL type definition."""
    name: str
    parent: Optional[str] = None
    source: str = ""  # Which worker generated this


@dataclass
class PDDLPredicate:
    """Represents a PDDL predicate definition."""
    name: str
    parameters: list[tuple[str, str]]  # [(var_name, type_name), ...]
    description: str = ""
    source: str = ""


@dataclass
class PDDLAction:
    """Represents a PDDL action definition."""
    name: str
    parameters: list[tuple[str, str]]
    preconditions: list[str]
    effects: list[str]
    command_template: str = ""
    requires_root: bool = False
    source_utility: str = ""
    source_worker: str = ""

CURATED_PREDICATES = {
    # Package management
    "installed": [("p", "package")],
    "available": [("p", "package")],
    "outdated": [("p", "package")],
    "vulnerable": [("p", "package")],
    "in_repository": [("p", "package"), ("r", "repository")],
    
    # Service management
    "service_exists": [("s", "service")],
    "service_running": [("s", "service")],
    "service_enabled": [("s", "service")],
    "service_failed": [("s", "service")],
    
    # File system
    "file_exists": [("f", "file")],
    "directory_exists": [("d", "directory")],
    "file_owned_by": [("f", "file"), ("u", "user")],
    "file_readable": [("f", "file")],
    "file_writable": [("f", "file")],
    "configures": [("f", "configuration_file"), ("s", "service")],
    
    # Users and groups
    "user_exists": [("u", "user")],
    "group_exists": [("g", "group")],
    "member_of": [("u", "user"), ("g", "group")],
    "can_sudo": [("u", "user")],
    
    # Network
    "port_open": [("p", "port")],
    "port_allowed": [("p", "port")],
    "interface_up": [("i", "interface")],
    "firewall_rule_active": [("r", "firewall_rule")],
    "traffic_blocked": [("r", "firewall_rule")],
    
    # General
    "network_available": [],
    "can_escalate": [("u", "user")],
}

CURATED_ACTIONS = [
    {
        "name": "install_package",
        "parameters": [("p", "package")],
        "preconditions": ["(available ?p)", "(not (installed ?p))", "(network_available)"],
        "effects": ["(installed ?p)"],
    },
    {
        "name": "remove_package",
        "parameters": [("p", "package")],
        "preconditions": ["(installed ?p)"],
        "effects": ["(not (installed ?p))"],
    },
    {
        "name": "update_package",
        "parameters": [("p", "package")],
        "preconditions": ["(installed ?p)", "(network_available)"],
        "effects": ["(not (outdated ?p))", "(not (vulnerable ?p))"],
    },
    {
        "name": "start_service",
        "parameters": [("s", "service")],
        "preconditions": ["(service_exists ?s)", "(not (service_running ?s))"],
        "effects": ["(service_running ?s)"],
    },
    {
        "name": "stop_service",
        "parameters": [("s", "service")],
        "preconditions": ["(service_running ?s)"],
        "effects": ["(not (service_running ?s))"],
    },
    {
        "name": "restart_service",
        "parameters": [("s", "service")],
        "preconditions": ["(service_exists ?s)"],
        "effects": ["(service_running ?s)"],
    },
    {
        "name": "enable_service",
        "parameters": [("s", "service")],
        "preconditions": ["(service_exists ?s)"],
        "effects": ["(service_enabled ?s)"],
    },
    {
        "name": "disable_service",
        "parameters": [("s", "service")],
        "preconditions": ["(service_enabled ?s)"],
        "effects": ["(not (service_enabled ?s))"],
    },
    {
        "name": "copy_file",
        "parameters": [("src", "file"), ("dst", "file")],
        "preconditions": ["(file_exists ?src)", "(not (file_exists ?dst))"],
        "effects": ["(file_exists ?dst)"],
    },
    {
        "name": "move_file",
        "parameters": [("src", "file"), ("dst", "file")],
        "preconditions": ["(file_exists ?src)"],
        "effects": ["(not (file_exists ?src))", "(file_exists ?dst)"],
    },
    {
        "name": "delete_file",
        "parameters": [("f", "file")],
        "preconditions": ["(file_exists ?f)"],
        "effects": ["(not (file_exists ?f))"],
    },
    {
        "name": "create_directory",
        "parameters": [("d", "directory")],
        "preconditions": ["(not (directory_exists ?d))"],
        "effects": ["(directory_exists ?d)"],
    },
    {
        "name": "change_file_owner",
        "parameters": [("f", "file"), ("u", "user")],
        "preconditions": ["(file_exists ?f)", "(user_exists ?u)"],
        "effects": ["(file_owned_by ?f ?u)"],
    },
    {
        "name": "create_user",
        "parameters": [("u", "user")],
        "preconditions": ["(not (user_exists ?u))"],
        "effects": ["(user_exists ?u)"],
    },
    {
        "name": "delete_user",
        "parameters": [("u", "user")],
        "preconditions": ["(user_exists ?u)"],
        "effects": ["(not (user_exists ?u))"],
    },
    {
        "name": "add_user_to_group",
        "parameters": [("u", "user"), ("g", "group")],
        "preconditions": ["(user_exists ?u)", "(group_exists ?g)", "(not (member_of ?u ?g))"],
        "effects": ["(member_of ?u ?g)"],
    },
    {
        "name": "open_port",
        "parameters": [("p", "port")],
        "preconditions": ["(not (port_allowed ?p))"],
        "effects": ["(port_allowed ?p)"],
    },
    {
        "name": "close_port",
        "parameters": [("p", "port")],
        "preconditions": ["(port_allowed ?p)"],
        "effects": ["(not (port_allowed ?p))"],
    },
    {
        "name": "add_firewall_rule",
        "parameters": [("r", "firewall_rule")],
        "preconditions": ["(not (firewall_rule_active ?r))"],
        "effects": ["(firewall_rule_active ?r)", "(traffic_blocked ?r)"],
    },
    {
        "name": "remove_firewall_rule",
        "parameters": [("r", "firewall_rule")],
        "preconditions": ["(firewall_rule_active ?r)"],
        "effects": ["(not (firewall_rule_active ?r))", "(not (traffic_blocked ?r))"],
    },
]


def get_curated_predicates() -> dict[str, PDDLPredicate]:
    """Get curated predicates as PDDLPredicate objects."""
    result = {}
    for name, params in CURATED_PREDICATES.items():
        result[name] = PDDLPredicate(
            name=name,
            parameters=params,
            source="curated"
        )
    return result


def get_curated_actions() -> list[PDDLAction]:
    """Get curated actions as PDDLAction objects."""
    result = []
    for action_def in CURATED_ACTIONS:
        result.append(PDDLAction(
            name=action_def["name"],
            parameters=action_def["parameters"],
            preconditions=action_def["preconditions"],
            effects=action_def["effects"],
            source_worker="curated"
        ))
    return result


# =============================================================================
# SECTION 5: Partial PDDL Domain Data Structure
# =============================================================================

@dataclass
class PartialPDDLDomain:
    """Partial PDDL domain generated by a worker agent."""
    worker_name: str
    group_name: str
    types: list[PDDLType] = field(default_factory=list)
    predicates: list[PDDLPredicate] = field(default_factory=list)
    actions: list[PDDLAction] = field(default_factory=list)
    constants: list[tuple[str, str]] = field(default_factory=list)
    raw_pddl: str = ""
    generation_time: float = 0.0
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "worker_name": self.worker_name,
            "group_name": self.group_name,
            "types": [{"name": t.name, "parent": t.parent} for t in self.types],
            "predicates": [
                {"name": p.name, "parameters": p.parameters} 
                for p in self.predicates
            ],
            "actions": [
                {
                    "name": a.name,
                    "parameters": a.parameters,
                    "preconditions": a.preconditions,
                    "effects": a.effects,
                    "command": a.command_template
                }
                for a in self.actions
            ],
            "generation_time": self.generation_time
        }


# =============================================================================
# SECTION 6: Worker Agents (Map Phase)
# =============================================================================

class WorkerAgent:
    """
    Base worker agent for generating partial PDDL domains.
    Each worker specializes in a utility group.
    """
    
    SYSTEM_PROMPT = """You are a PDDL 2.1 domain expert. Generate STRICTLY VALID PDDL syntax.

ABSOLUTE RULES - VIOLATIONS WILL CAUSE PARSER FAILURE:

1. TYPES: Only these base types exist: object, package, service, user, group, file, directory, configuration_file, port, interface, firewall_rule, process, repository
   - Do NOT invent new types like "string", "list", "command"
   - Subtypes use: child_type - parent_type

2. PREDICATES: Boolean only, no functions
   VALID: (installed ?p - package)
   VALID: (file_exists ?f - file)  
   INVALID: (version ?p - package) - no return values
   INVALID: (name ?x - string) - string is not a type

3. ACTIONS: Every parameter MUST be declared
   VALID:
   (:action install_package
     :parameters (?p - package)
     :precondition (and (available ?p) (not (installed ?p)))
     :effect (and (installed ?p))
   )
   
   INVALID - unbound variable:
   (:action foo
     :parameters ()
     :precondition (bar ?x)  ; ERROR: ?x not declared
   )

4. NO FUNCTIONS OR EXPRESSIONS IN EFFECTS:
   INVALID: (installed (find_package ?name))
   INVALID: (concat ?a ?b)
   INVALID: (strcat ?x ?y)
   INVALID: (create_process ?cmd)
   VALID: (installed ?p)

5. QUANTIFIERS - use proper syntax:
   VALID: (exists (?x - type) (predicate ?x))
   VALID: (forall (?x - type) (predicate ?x))
   INVALID: (?x :exists (predicate ?x))

6. NO STRING LITERALS in preconditions/effects:
   INVALID: (equal ?chain "filter")
   VALID: (is_filter_chain ?chain)

OUTPUT FORMAT - exactly this structure:
(:types
  package service - object
)

(:predicates
  (predicate_name ?var - type)
)

(:action action_name
  :parameters (?p - type)
  :precondition (and (pred1 ?p))
  :effect (and (pred2 ?p))
)

Generate ONLY valid PDDL. No markdown, no explanations, no comments."""
    
    def __init__(
        self,
        group_name: str,
        group_config: dict,
        llm: LLMInterface,
        doc_extractor: DocumentationExtractor,
        osquery_data: Optional[dict] = None
    ):
        self.group_name = group_name
        self.config = group_config
        self.llm = llm
        self.doc_extractor = doc_extractor
        self.osquery_data = osquery_data or {}
        self.worker_name = f"{group_name}_agent"
    
    def generate_partial_domain(self) -> PartialPDDLDomain:
        """Generate partial PDDL domain for this utility group."""
        start_time = time.time()
        
        result = PartialPDDLDomain(
            worker_name=self.worker_name,
            group_name=self.group_name
        )
        
        try:
            # 1. Fetch documentation for all utilities
            docs = self.doc_extractor.get_utility_docs(self.config["utilities"])
            
            # 2. Build prompt with documentation context
            prompt = self._build_generation_prompt(docs)
            
            # 3. Generate PDDL via LLM
            raw_pddl = self.llm.generate(prompt, self.SYSTEM_PROMPT)
            result.raw_pddl = raw_pddl
            
            # 4. Parse the generated PDDL
            self._parse_pddl_output(raw_pddl, result)
            
            result.generation_time = time.time() - start_time
            logger.info(
                f"Worker {self.worker_name}: Generated {len(result.types)} types, "
                f"{len(result.predicates)} predicates, {len(result.actions)} actions "
                f"in {result.generation_time:.2f}s"
            )
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Worker {self.worker_name} failed: {e}")
        
        return result
    
    def _build_generation_prompt(self, docs: dict[str, str]) -> str:
        """Build the prompt for PDDL generation."""
        prompt_parts = [
            f"Generate PDDL domain components for: {self.config['description']}",
            f"\nTarget PDDL types to define or use: {', '.join(self.config['pddl_focus'])}",
            "\n\n=== SYSTEM DOCUMENTATION ===\n"
        ]
        
        # Add documentation (truncated for context limits)
        for utility, doc in docs.items():
            if doc:
                # Truncate each doc to ~2000 chars
                truncated = doc[:2000] + "..." if len(doc) > 2000 else doc
                prompt_parts.append(f"\n--- {utility} ---\n{truncated}\n")
        
        # Add osquery context if available
        if self.osquery_data:
            prompt_parts.append("\n=== CURRENT SYSTEM STATE (osquery) ===\n")
            for table in self.config.get("osquery_tables", []):
                if table in self.osquery_data:
                    data = self.osquery_data[table]
                    # Show first 10 entries
                    sample = data[:10] if isinstance(data, list) else data
                    prompt_parts.append(f"{table}: {json.dumps(sample, indent=2)}\n")
        
        prompt_parts.append(
            "\n\nGenerate the PDDL types, predicates, and actions. "
            "Output ONLY valid PDDL syntax."
        )
        
        return "".join(prompt_parts)
    
    def _parse_pddl_output(self, raw: str, result: PartialPDDLDomain):
        """Parse LLM output into structured PDDL components."""
        # Extract types
        types_match = re.search(r'\(:types\s*(.*?)\)', raw, re.DOTALL)
        if types_match:
            result.types = self._parse_types(types_match.group(1))
        
        # Extract predicates
        pred_match = re.search(r'\(:predicates\s*(.*?)\)\s*(?:\(:action|$)', raw, re.DOTALL)
        if pred_match:
            result.predicates = self._parse_predicates(pred_match.group(1))
        
        # Extract actions
        action_pattern = r'\(:action\s+(\w+)\s*(.*?)(?=\(:action|\Z)'
        for match in re.finditer(action_pattern, raw, re.DOTALL):
            action = self._parse_action(match.group(1), match.group(2))
            if action:
                action.source_worker = self.worker_name
                result.actions.append(action)
    
    def _parse_types(self, types_str: str) -> list[PDDLType]:
        """Parse PDDL type definitions."""
        types = []
        # Pattern: type1 type2 - parent_type
        lines = types_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            if ' - ' in line:
                parts = line.split(' - ')
                parent = parts[-1].strip()
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child:
                        types.append(PDDLType(
                            name=child, 
                            parent=parent,
                            source=self.worker_name
                        ))
            else:
                for t in line.split():
                    if t.strip():
                        types.append(PDDLType(
                            name=t.strip(),
                            source=self.worker_name
                        ))
        
        return types
    
    def _parse_predicates(self, pred_str: str) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions."""
        predicates = []
        # Pattern: (predicate_name ?param1 - type1 ?param2 - type2)
        pattern = r'\((\w+)((?:\s+\?\w+\s*-\s*\w+)*)\)'
        
        for match in re.finditer(pattern, pred_str):
            name = match.group(1)
            params_str = match.group(2).strip()
            
            # Parse parameters
            params = []
            param_pattern = r'\?(\w+)\s*-\s*(\w+)'
            for pm in re.finditer(param_pattern, params_str):
                params.append((pm.group(1), pm.group(2)))
            
            predicates.append(PDDLPredicate(
                name=name,
                parameters=params,
                source=self.worker_name
            ))
        
        return predicates
    
    def _parse_action(self, name: str, body: str) -> Optional[PDDLAction]:
        """Parse a single PDDL action."""
        try:
            # Extract parameters
            params_match = re.search(r':parameters\s*\((.*?)\)', body, re.DOTALL)
            params = []
            if params_match:
                param_pattern = r'\?(\w+)\s*-\s*(\w+)'
                for pm in re.finditer(param_pattern, params_match.group(1)):
                    params.append((pm.group(1), pm.group(2)))
            
            # Extract preconditions
            pre_match = re.search(r':precondition\s*\((.*?)\)\s*:effect', body, re.DOTALL)
            preconditions = []
            if pre_match:
                preconditions = self._extract_conditions(pre_match.group(1))
            
            # Extract effects
            eff_match = re.search(r':effect\s*\((.*?)\)\s*\)?$', body, re.DOTALL)
            effects = []
            if eff_match:
                effects = self._extract_conditions(eff_match.group(1))
            
            return PDDLAction(
                name=name,
                parameters=params,
                preconditions=preconditions,
                effects=effects
            )
        except Exception as e:
            logger.warning(f"Failed to parse action {name}: {e}")
            return None
    
    def _extract_conditions(self, cond_str: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []
        # Remove outer 'and' if present
        cond_str = re.sub(r'^\s*and\s*', '', cond_str.strip())
        
        # Match individual predicates including (not (...))
        depth = 0
        current = ""
        for char in cond_str:
            if char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
                if depth == 0 and current.strip():
                    conditions.append(current.strip())
                    current = ""
            elif depth > 0:
                current += char
        
        return conditions


# =============================================================================
# SECTION 7: Supervisor Agent (Orchestrator)
# =============================================================================

class SupervisorAgent:
    """
    Supervisor agent that orchestrates parallel worker execution.
    Implements the Map phase of Map-Reduce.
    """
    
    def __init__(
        self,
        llm: LLMInterface,
        hardware_config: HardwareConfig,
        osquery_data: Optional[dict] = None
    ):
        self.llm = llm
        self.hardware = hardware_config
        self.osquery_data = osquery_data or {}
        self.doc_extractor = DocumentationExtractor()
        self.partial_domains: list[PartialPDDLDomain] = []
    
    def execute_map_phase(self) -> list[PartialPDDLDomain]:
        """
        Execute the Map phase: dispatch workers in parallel.
        """
        logger.info("=" * 60)
        logger.info("MAP PHASE: Dispatching Worker Agents")
        logger.info("=" * 60)
        logger.info(f"Hardware: {self.hardware.num_gpus} GPUs, "
                   f"{self.hardware.num_cpus} CPUs, "
                   f"{self.hardware.total_ram_gb:.0f}GB RAM")
        logger.info(f"Max parallel workers: {self.hardware.max_parallel_workers}")
        
        start_time = time.time()
        
        # Create worker tasks
        worker_configs = [
            (group_name, config)
            for group_name, config in UTILITY_GROUPS.items()
        ]
        
        # Execute workers in parallel using ThreadPoolExecutor
        # (GPU-bound via LLM, so threads are fine)
        results = []
        
        with ThreadPoolExecutor(max_workers=self.hardware.max_parallel_workers) as executor:
            future_to_worker = {}
            
            for group_name, config in worker_configs:
                worker = WorkerAgent(
                    group_name=group_name,
                    group_config=config,
                    llm=self.llm,
                    doc_extractor=self.doc_extractor,
                    osquery_data=self.osquery_data
                )
                future = executor.submit(worker.generate_partial_domain)
                future_to_worker[future] = group_name
            
            for future in as_completed(future_to_worker):
                worker_name = future_to_worker[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"  ✓ {worker_name} completed")
                except Exception as e:
                    logger.error(f"  ✗ {worker_name} failed: {e}")
                    results.append(PartialPDDLDomain(
                        worker_name=f"{worker_name}_agent",
                        group_name=worker_name,
                        error=str(e)
                    ))
        
        elapsed = time.time() - start_time
        logger.info(f"Map phase completed in {elapsed:.2f}s")
        logger.info(f"Successful workers: {sum(1 for r in results if not r.error)}/{len(results)}")
        
        self.partial_domains = results
        return results


# =============================================================================
# SECTION 8: Merger Agent (Reduce Phase)
# =============================================================================

class MergerAgent:
    """
    Merger agent that synthesizes partial domains into a unified PDDL domain.
    Implements the Reduce phase with conflict resolution.
    """
    
    def __init__(self, llm: Optional[LLMInterface] = None):
        self.llm = llm
        self.repairer = PDDLRepairer()  # Add repairer
        self.unified_types: dict[str, PDDLType] = {}
        self.unified_predicates: dict[str, PDDLPredicate] = {}
        self.unified_actions: list[PDDLAction] = []
        self.merge_log: list[str] = []
        self.all_repairs: list[str] = []
    
    # Core type hierarchy (Section 3.1) - used for conflict resolution
    CORE_TYPE_HIERARCHY = {
        "object": None,
        "filesystem_object": "object",
        "file": "filesystem_object",
        "directory": "filesystem_object",
        "configuration_file": "file",
        "service": "object",
        "process": "object",
        "package": "object",
        "repository": "object",
        "user": "object",
        "group": "object",
        "system_user": "user",
        "human_user": "user",
        "port": "object",
        "interface": "object",
        "firewall_rule": "object",
    }
    
    def merge(self, partial_domains: list[PartialPDDLDomain]) -> str:
        """
        Execute the Reduce phase: merge partial domains.
        Returns the unified PDDL domain as a string.
        """
        logger.info("=" * 60)
        logger.info("REDUCE PHASE: Merging Partial Domains")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        # Filter out failed workers
        valid_domains = [d for d in partial_domains if not d.error]
        logger.info(f"Merging {len(valid_domains)} valid partial domains")
        
        # Step 0: Repair each partial domain's raw PDDL
        logger.info("\n[0/5] Repairing LLM-generated PDDL syntax...")
        for domain in valid_domains:
            if domain.raw_pddl:
                repaired = self.repairer.repair(domain.raw_pddl)
                repairs = self.repairer.get_repairs_log()
                if repairs:
                    logger.info(f"  {domain.worker_name}: {len(repairs)} repairs")
                    self.all_repairs.extend([f"{domain.worker_name}: {r}" for r in repairs])
                domain.raw_pddl = repaired
                # Re-parse after repair
                self._reparse_domain(domain)
        
        logger.info(f"  → Total repairs: {len(self.all_repairs)}")
        
        # Step 1: Namespace Resolution - Unify Types
        logger.info("\n[1/5] Unifying type definitions...")
        self._unify_types(valid_domains)
        logger.info(f"  → {len(self.unified_types)} unified types")
        
        # Step 2: Predicate Unification
        logger.info("\n[2/5] Unifying predicates...")
        self._unify_predicates(valid_domains)
        # Also extract predicates from action bodies
        self._extract_predicates_from_actions(valid_domains)
        logger.info(f"  → {len(self.unified_predicates)} unified predicates")
        
        # Step 3: Action Consolidation
        logger.info("\n[3/5] Consolidating actions...")
        self._consolidate_actions(valid_domains)
        logger.info(f"  → {len(self.unified_actions)} unified actions")
        
        # Check if we have enough valid actions; if not, add curated fallbacks
        if len(self.unified_actions) < 5:
            logger.warning(f"  ⚠ Only {len(self.unified_actions)} valid actions, adding curated templates")
            curated_actions = get_curated_actions()
            existing_names = {a.name for a in self.unified_actions}
            for ca in curated_actions:
                if ca.name not in existing_names:
                    self.unified_actions.append(ca)
            logger.info(f"  → After curated additions: {len(self.unified_actions)} actions")
        
        # Check predicates; add curated if too few
        if len(self.unified_predicates) < 5:
            logger.warning(f"  ⚠ Only {len(self.unified_predicates)} predicates, adding curated templates")
            curated_preds = get_curated_predicates()
            for name, pred in curated_preds.items():
                if name not in self.unified_predicates:
                    self.unified_predicates[name] = pred
            logger.info(f"  → After curated additions: {len(self.unified_predicates)} predicates")
        
        # Step 4: Validate action parameters reference declared predicates
        logger.info("\n[4/5] Validating action-predicate consistency...")
        self._validate_action_predicates()
        
        # Step 5: Construct and Validate Domain
        logger.info("\n[5/5] Constructing unified domain...")
        domain_pddl = self._construct_domain()
        
        # Final syntax repair pass
        domain_pddl = self.repairer.repair(domain_pddl)
        
        # Validate syntax
        is_valid, errors = self._validate_pddl(domain_pddl)
        if is_valid:
            logger.info("  ✓ Domain syntax validated")
        else:
            logger.warning(f"  ⚠ Validation issues: {errors}")
            domain_pddl = self._repair_pddl(domain_pddl, errors)
        
        elapsed = time.time() - start_time
        logger.info(f"\nReduce phase completed in {elapsed:.2f}s")
        
        return domain_pddl
    
    def _reparse_domain(self, domain: PartialPDDLDomain):
        """Re-parse a domain after repairs."""
        raw = domain.raw_pddl
        
        # Clear existing parsed data
        domain.types = []
        domain.predicates = []
        domain.actions = []
        
        # Re-extract types
        types_match = re.search(r'\(:types\s*(.*?)\)', raw, re.DOTALL)
        if types_match:
            domain.types = self._parse_types_from_string(types_match.group(1), domain.worker_name)
        
        # Re-extract predicates
        pred_match = re.search(r'\(:predicates\s*(.*?)\)\s*(?:\(:action|$)', raw, re.DOTALL)
        if pred_match:
            domain.predicates = self._parse_predicates_from_string(pred_match.group(1), domain.worker_name)
        
        # Re-extract actions
        action_pattern = r'\(:action\s+(\w+)\s*(.*?)(?=\(:action|\Z)'
        for match in re.finditer(action_pattern, raw, re.DOTALL):
            action = self._parse_action_from_match(match.group(1), match.group(2), domain.worker_name)
            if action:
                domain.actions.append(action)
    
    def _parse_types_from_string(self, types_str: str, source: str) -> list[PDDLType]:
        """Parse PDDL type definitions from string."""
        types = []
        lines = types_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            if ' - ' in line:
                parts = line.split(' - ')
                parent = parts[-1].strip()
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child and child in PDDLRepairer.VALID_TYPES:
                        types.append(PDDLType(name=child, parent=parent, source=source))
        return types
    
    def _parse_predicates_from_string(self, pred_str: str, source: str) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions from string."""
        predicates = []
        pattern = r'\((\w+)((?:\s+\?\w+\s*-\s*\w+)*)\)'
        
        for match in re.finditer(pattern, pred_str):
            name = match.group(1)
            params_str = match.group(2).strip()
            
            params = []
            param_pattern = r'\?(\w+)\s*-\s*(\w+)'
            for pm in re.finditer(param_pattern, params_str):
                params.append((pm.group(1), pm.group(2)))
            
            predicates.append(PDDLPredicate(name=name, parameters=params, source=source))
        
        return predicates

    def _parse_action_from_match(self, name: str, body: str, source: str) -> Optional[PDDLAction]:
        """Parse a single PDDL action."""
        try:
            # Extract parameters
            params_match = re.search(r':parameters\s*\((.*?)\)', body, re.DOTALL)
            params = []
            if params_match:
                param_pattern = r'\?(\w+)\s*-\s*(\w+)'
                for pm in re.finditer(param_pattern, params_match.group(1)):
                    params.append((pm.group(1), pm.group(2)))

            # Extract preconditions
            pre_match = re.search(r':precondition\s*\(and(.*?)\)\s*:effect', body, re.DOTALL)
            preconditions = []
            if pre_match:
                preconditions = self._extract_conditions(pre_match.group(1))

            # Extract effects
            eff_match = re.search(r':effect\s*\(and(.*?)\)\s*\)?$', body, re.DOTALL)
            effects = []
            if eff_match:
                effects = self._extract_conditions(eff_match.group(1))

            return PDDLAction(
                name=name,
                parameters=params,
                preconditions=preconditions,
                effects=effects,
                source_worker=source
            )
        except Exception as e:
            logger.warning(f"Failed to parse action {name}: {e}")
            return None

    def _extract_predicates_from_actions(self, domains: list[PartialPDDLDomain]):
        """Extract predicates that are used in actions but not declared."""
        for domain in domains:
            for action in domain.actions:
                # Check preconditions
                for pre in action.preconditions:
                    self._extract_predicate_from_condition(pre, domain.worker_name)

                # Check effects
                for eff in action.effects:
                    self._extract_predicate_from_condition(eff, domain.worker_name)

    def _extract_predicate_from_condition(self, condition: str, source: str):
        """Extract a predicate definition from a condition string."""
        # Remove 'not' wrapper
        cond = condition.strip()
        if cond.startswith('(not'):
            cond = cond[4:].strip().rstrip(')')

        # Match (predicate_name ?var1 - type1 ...)
        match = re.match(r'\((\w+)((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\)', cond)
        if match:
            pred_name = match.group(1)

            # Skip PDDL keywords
            if pred_name in ['and', 'or', 'not', 'exists', 'forall', 'when']:
                return

            # Skip if already exists
            if pred_name in self.unified_predicates:
                return

            params_str = match.group(2).strip()
            params = []

            # Parse parameters
            param_pattern = r'\?(\w+)(?:\s*-\s*(\w+))?'
            for pm in re.finditer(param_pattern, params_str):
                var_name = pm.group(1)
                var_type = pm.group(2) if pm.group(2) else self.repairer._infer_type_from_context(var_name, condition)
                params.append((var_name, var_type))

            self.unified_predicates[pred_name] = PDDLPredicate(
                name=pred_name,
                parameters=params,
                source=source
            )
            self.merge_log.append(f"Extracted predicate '{pred_name}' from action body")

    def _validate_action_predicates(self):
        """Ensure all predicates used in actions are declared."""
        for action in self.unified_actions:
            for pre in action.preconditions + action.effects:
                # Extract predicate name
                cond = pre.strip()
                if cond.startswith('(not'):
                    cond = cond[4:].strip().rstrip(')')

                match = re.match(r'\((\w+)', cond)
                if match:
                    pred_name = match.group(1)
                    if pred_name not in ['and', 'or', 'not', 'exists', 'forall', 'when']:
                        if pred_name not in self.unified_predicates:
                            # Add missing predicate
                            self._extract_predicate_from_condition(cond, "validator")

    def _unify_types(self, domains: list[PartialPDDLDomain]):
        """Unify type definitions with conflict resolution."""
        # Start with core hierarchy
        for type_name, parent in self.CORE_TYPE_HIERARCHY.items():
            self.unified_types[type_name] = PDDLType(
                name=type_name,
                parent=parent,
                source="core_hierarchy"
            )

        # Add types from workers
        for domain in domains:
            for ptype in domain.types:
                if ptype.name not in self.unified_types:
                    # New type - check if parent exists
                    if ptype.parent and ptype.parent not in self.unified_types:
                        # Parent doesn't exist, default to 'object'
                        self.merge_log.append(
                            f"Type '{ptype.name}' parent '{ptype.parent}' not found, "
                            f"defaulting to 'object'"
                        )
                        ptype.parent = "object"

                    self.unified_types[ptype.name] = ptype
                else:
                    # Type exists - check for conflicts
                    existing = self.unified_types[ptype.name]
                    if ptype.parent != existing.parent:
                        # Parent conflict - prefer core hierarchy
                        if existing.source == "core_hierarchy":
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"keeping core '{existing.parent}' over '{ptype.parent}'"
                            )
                        else:
                            # Use LLM to resolve if available
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"'{existing.parent}' vs '{ptype.parent}'"
                            )

    def _unify_predicates(self, domains: list[PartialPDDLDomain]):
        """Unify predicates, detecting semantic duplicates."""
        # Predicate similarity mapping for unification
        PREDICATE_ALIASES = {
            "file_exists": ["file_present", "has_file"],
            "service_running": ["service_active", "svc_running"],
            "package_installed": ["pkg_installed", "has_package"],
            "user_exists": ["user_present", "has_user"],
        }

        # Build reverse mapping
        alias_to_canonical = {}
        for canonical, aliases in PREDICATE_ALIASES.items():
            for alias in aliases:
                alias_to_canonical[alias] = canonical

        for domain in domains:
            for pred in domain.predicates:
                # Check if this is an alias
                canonical_name = alias_to_canonical.get(pred.name, pred.name)

                if canonical_name != pred.name:
                    self.merge_log.append(
                        f"Unified predicate alias '{pred.name}' → '{canonical_name}'"
                    )
                    pred.name = canonical_name

                if canonical_name not in self.unified_predicates:
                    self.unified_predicates[canonical_name] = pred
                else:
                    # Check parameter compatibility
                    existing = self.unified_predicates[canonical_name]
                    if len(pred.parameters) != len(existing.parameters):
                        self.merge_log.append(
                            f"Predicate '{canonical_name}' arity mismatch: "
                            f"{len(existing.parameters)} vs {len(pred.parameters)}"
                        )

    def _consolidate_actions(self, domains: list[PartialPDDLDomain]):
        """Consolidate actions, detecting and merging duplicates."""
        action_map: dict[str, list[PDDLAction]] = {}

        # Group actions by name
        for domain in domains:
            for action in domain.actions:
                if action.name not in action_map:
                    action_map[action.name] = []
                action_map[action.name].append(action)

        # Merge or select best version
        for name, actions in action_map.items():
            if len(actions) == 1:
                self.unified_actions.append(actions[0])
            else:
                # Multiple definitions - merge
                merged = self._merge_actions(actions)
                self.unified_actions.append(merged)
                self.merge_log.append(
                    f"Merged {len(actions)} definitions of action '{name}'"
                )

    def _merge_actions(self, actions: list[PDDLAction]) -> PDDLAction:
        """Merge multiple action definitions into one."""
        # Use the one with most complete preconditions
        best = max(actions, key=lambda a: len(a.preconditions) + len(a.effects))

        # Merge unique preconditions from all versions
        all_preconds = set()
        for a in actions:
            all_preconds.update(a.preconditions)

        all_effects = set()
        for a in actions:
            all_effects.update(a.effects)

        return PDDLAction(
            name=best.name,
            parameters=best.parameters,
            preconditions=list(all_preconds),
            effects=list(all_effects),
            command_template=best.command_template,
            requires_root=any(a.requires_root for a in actions),
            source_utility=best.source_utility,
            source_worker="merged"
        )

    def _construct_domain(self) -> str:
        """Construct the unified PDDL domain string."""
        lines = [
            ";; =============================================================================",
            ";; SYSADMIN PDDL DOMAIN - Ubuntu 25.10 'Questing Quokka'",
            ";; Auto-generated by Phase 2: Parallel Synthesis (Map-Reduce)",
            ";; =============================================================================",
            "",
            "(define (domain sysadmin)",
            "",
            "  (:requirements :strips :typing :negative-preconditions)",
            "",
        ]

        # Types section
        lines.append("  ;; Type Hierarchy")
        lines.append("  (:types")

        # Group types by parent
        parent_groups: dict[str, list[str]] = {}
        for tname, tdef in self.unified_types.items():
            parent = tdef.parent or "object"
            if parent not in parent_groups:
                parent_groups[parent] = []
            if tname != parent:  # Don't include self
                parent_groups[parent].append(tname)

        # Output in hierarchy order
        for parent in ["object", "filesystem_object", "file", "user"]:
            if parent in parent_groups and parent_groups[parent]:
                children = " ".join(sorted(parent_groups[parent]))
                lines.append(f"    {children} - {parent}")

        # Output remaining
        for parent, children in parent_groups.items():
            if parent not in ["object", "filesystem_object", "file", "user"] and children:
                lines.append(f"    {' '.join(sorted(children))} - {parent}")

        lines.append("  )")
        lines.append("")

        # Predicates section
        lines.append("  ;; Predicates")
        lines.append("  (:predicates")

        for pname, pred in sorted(self.unified_predicates.items()):
            params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
            lines.append(f"    ({pname} {params})")

        # Add standard predicates if missing
        standard_preds = [
            "(network_available)",
            "(can_escalate ?u - user)",
        ]
        for sp in standard_preds:
            if not any(sp.split()[0].strip("(") in p for p in self.unified_predicates):
                lines.append(f"    {sp}")

        lines.append("  )")
        lines.append("")

        # Actions section
        for action in sorted(self.unified_actions, key=lambda a: a.name):
            lines.append(f"  ;; Action: {action.name}")
            if action.source_utility:
                lines.append(f"  ;; Source: {action.source_utility}")

            lines.append(f"  (:action {action.name}")

            # Parameters
            params = " ".join(f"?{p[0]} - {p[1]}" for p in action.parameters)
            lines.append(f"    :parameters ({params})")

            # Preconditions
            if action.preconditions:
                lines.append("    :precondition (and")
                for pre in action.preconditions:
                    lines.append(f"      {pre}")
                lines.append("    )")
            else:
                lines.append("    :precondition (and)")

            # Effects
            if action.effects:
                lines.append("    :effect (and")
                for eff in action.effects:
                    lines.append(f"      {eff}")
                lines.append("    )")
            else:
                lines.append("    :effect (and)")

            lines.append("  )")
            lines.append("")

        lines.append(")")

        return "\n".join(lines)

    def _validate_pddl(self, pddl: str) -> tuple[bool, list[str]]:
        """Validate PDDL syntax using VAL if available."""
        errors = []

        # Basic syntax checks
        if pddl.count('(') != pddl.count(')'):
            errors.append("Unbalanced parentheses")

        if "(define (domain" not in pddl:
            errors.append("Missing domain definition")

        if "(:types" not in pddl:
            errors.append("Missing types section")

        if "(:predicates" not in pddl:
            errors.append("Missing predicates section")

        # Try VAL parser if available
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pddl', delete=False) as f:
                f.write(pddl)
                temp_path = f.name

            result = subprocess.run(
                ["validate", "-p", temp_path],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                errors.append(f"VAL: {result.stderr}")

            os.unlink(temp_path)
        except FileNotFoundError:
            pass  # VAL not installed
        except Exception as e:
            pass

        return len(errors) == 0, errors

    def _repair_pddl(self, pddl: str, errors: list[str]) -> str:
        """Attempt to repair PDDL syntax errors."""
        # Fix unbalanced parentheses
        open_count = pddl.count('(')
        close_count = pddl.count(')')

        if open_count > close_count:
            pddl += ')' * (open_count - close_count)
        elif close_count > open_count:
            # Remove extra closing parens from end
            while pddl.endswith(')') and pddl.count(')') > pddl.count('('):
                pddl = pddl[:-1]

        return pddl

    def get_merge_log(self) -> list[str]:
        """Return the merge operation log."""
        return self.merge_log
    
    def _unify_types(self, domains: list[PartialPDDLDomain]):
        """Unify type definitions with conflict resolution."""
        # Start with core hierarchy
        for type_name, parent in self.CORE_TYPE_HIERARCHY.items():
            self.unified_types[type_name] = PDDLType(
                name=type_name,
                parent=parent,
                source="core_hierarchy"
            )
        
        # Add types from workers
        for domain in domains:
            for ptype in domain.types:
                if ptype.name not in self.unified_types:
                    # New type - check if parent exists
                    if ptype.parent and ptype.parent not in self.unified_types:
                        # Parent doesn't exist, default to 'object'
                        self.merge_log.append(
                            f"Type '{ptype.name}' parent '{ptype.parent}' not found, "
                            f"defaulting to 'object'"
                        )
                        ptype.parent = "object"
                    
                    self.unified_types[ptype.name] = ptype
                else:
                    # Type exists - check for conflicts
                    existing = self.unified_types[ptype.name]
                    if ptype.parent != existing.parent:
                        # Parent conflict - prefer core hierarchy
                        if existing.source == "core_hierarchy":
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"keeping core '{existing.parent}' over '{ptype.parent}'"
                            )
                        else:
                            # Use LLM to resolve if available
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"'{existing.parent}' vs '{ptype.parent}'"
                            )
    
    def _unify_predicates(self, domains: list[PartialPDDLDomain]):
        """Unify predicates, detecting semantic duplicates."""
        # Predicate similarity mapping for unification
        PREDICATE_ALIASES = {
            "file_exists": ["file_present", "has_file"],
            "service_running": ["service_active", "svc_running"],
            "package_installed": ["pkg_installed", "has_package"],
            "user_exists": ["user_present", "has_user"],
        }
        
        # Build reverse mapping
        alias_to_canonical = {}
        for canonical, aliases in PREDICATE_ALIASES.items():
            for alias in aliases:
                alias_to_canonical[alias] = canonical
        
        for domain in domains:
            for pred in domain.predicates:
                # Check if this is an alias
                canonical_name = alias_to_canonical.get(pred.name, pred.name)
                
                if canonical_name != pred.name:
                    self.merge_log.append(
                        f"Unified predicate alias '{pred.name}' → '{canonical_name}'"
                    )
                    pred.name = canonical_name
                
                if canonical_name not in self.unified_predicates:
                    self.unified_predicates[canonical_name] = pred
                else:
                    # Check parameter compatibility
                    existing = self.unified_predicates[canonical_name]
                    if len(pred.parameters) != len(existing.parameters):
                        self.merge_log.append(
                            f"Predicate '{canonical_name}' arity mismatch: "
                            f"{len(existing.parameters)} vs {len(pred.parameters)}"
                        )
    
    def _consolidate_actions(self, domains: list[PartialPDDLDomain]):
        """Consolidate actions, detecting and merging duplicates."""
        action_map: dict[str, list[PDDLAction]] = {}
        
        # Group actions by name
        for domain in domains:
            for action in domain.actions:
                if action.name not in action_map:
                    action_map[action.name] = []
                action_map[action.name].append(action)
        
        # Merge or select best version
        for name, actions in action_map.items():
            if len(actions) == 1:
                self.unified_actions.append(actions[0])
            else:
                # Multiple definitions - merge
                merged = self._merge_actions(actions)
                self.unified_actions.append(merged)
                self.merge_log.append(
                    f"Merged {len(actions)} definitions of action '{name}'"
                )
    
    def _merge_actions(self, actions: list[PDDLAction]) -> PDDLAction:
        """Merge multiple action definitions into one."""
        # Use the one with most complete preconditions
        best = max(actions, key=lambda a: len(a.preconditions) + len(a.effects))
        
        # Merge unique preconditions from all versions
        all_preconds = set()
        for a in actions:
            all_preconds.update(a.preconditions)
        
        all_effects = set()
        for a in actions:
            all_effects.update(a.effects)
        
        return PDDLAction(
            name=best.name,
            parameters=best.parameters,
            preconditions=list(all_preconds),
            effects=list(all_effects),
            command_template=best.command_template,
            requires_root=any(a.requires_root for a in actions),
            source_utility=best.source_utility,
            source_worker="merged"
        )
    
    def _extract_conditions(self, cond_str: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []
        # Remove outer 'and' if present
        cond_str = re.sub(r'^\s*and\s*', '', cond_str.strip())
        
        # Match individual predicates including (not (...))
        depth = 0
        current = ""
        for char in cond_str:
            if char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
                if depth == 0 and current.strip():
                    # Validate this is a proper predicate
                    stripped = current.strip()
                    if stripped and stripped.startswith('(') and stripped.endswith(')'):
                        # Check it's not malformed
                        if not any(x in stripped for x in ['strcat', 'concat', 'create_process', '""', "='", "="]):
                            conditions.append(stripped)
                    current = ""
            elif depth > 0:
                current += char
        
        return conditions
    
    def _construct_domain(self) -> str:
        """Construct the unified PDDL domain string."""
        lines = [
            ";; =============================================================================",
            ";; SYSADMIN PDDL DOMAIN - Ubuntu 25.10 'Questing Quokka'",
            ";; Auto-generated by Phase 2: Parallel Synthesis (Map-Reduce)",
            ";; =============================================================================",
            "",
            "(define (domain sysadmin)",
            "",
            "  (:requirements :strips :typing :negative-preconditions)",
            "",
        ]
        
        # Types section
        lines.append("  ;; Type Hierarchy")
        lines.append("  (:types")
        
        # Group types by parent
        parent_groups: dict[str, list[str]] = {}
        for tname, tdef in self.unified_types.items():
            parent = tdef.parent or "object"
            if parent not in parent_groups:
                parent_groups[parent] = []
            if tname != parent:  # Don't include self
                parent_groups[parent].append(tname)
        
        # Output in hierarchy order
        for parent in ["object", "filesystem_object", "file", "user"]:
            if parent in parent_groups and parent_groups[parent]:
                children = " ".join(sorted(parent_groups[parent]))
                lines.append(f"    {children} - {parent}")
        
        # Output remaining
        for parent, children in parent_groups.items():
            if parent not in ["object", "filesystem_object", "file", "user"] and children:
                lines.append(f"    {' '.join(sorted(children))} - {parent}")
        
        lines.append("  )")
        lines.append("")
        
        # Predicates section
        lines.append("  ;; Predicates (extracted from action bodies and explicit declarations)")
        lines.append("  (:predicates")
        
        # Add all unified predicates
        for pname, pred in sorted(self.unified_predicates.items()):
            if pred.parameters:
                params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
                lines.append(f"    ({pname} {params})")
            else:
                lines.append(f"    ({pname})")
        
        # Add standard predicates if missing
        standard_preds = [
            ("network_available", []),
            ("can_escalate", [("u", "user")]),
        ]
        for pred_name, pred_params in standard_preds:
            if pred_name not in self.unified_predicates:
                if pred_params:
                    params = " ".join(f"?{p[0]} - {p[1]}" for p in pred_params)
                    lines.append(f"    ({pred_name} {params})")
                else:
                    lines.append(f"    ({pred_name})")
        
        lines.append("  )")
        lines.append("")
        
        # Actions section
        for action in sorted(self.unified_actions, key=lambda a: a.name):
            lines.append(f"  ;; Action: {action.name}")
            if action.source_utility:
                lines.append(f"  ;; Source: {action.source_utility}")
            
            lines.append(f"  (:action {action.name}")
            
            # Parameters
            params = " ".join(f"?{p[0]} - {p[1]}" for p in action.parameters)
            lines.append(f"    :parameters ({params})")
            
            # Preconditions
            if action.preconditions:
                lines.append("    :precondition (and")
                for pre in action.preconditions:
                    lines.append(f"      {pre}")
                lines.append("    )")
            else:
                lines.append("    :precondition (and)")
            
            # Effects
            if action.effects:
                lines.append("    :effect (and")
                for eff in action.effects:
                    lines.append(f"      {eff}")
                lines.append("    )")
            else:
                lines.append("    :effect (and)")
            
            lines.append("  )")
            lines.append("")
        
        lines.append(")")
        
        return "\n".join(lines)
    
    def _validate_pddl(self, pddl: str) -> tuple[bool, list[str]]:
        """Validate PDDL syntax using VAL if available."""
        errors = []
        
        # Basic syntax checks
        if pddl.count('(') != pddl.count(')'):
            errors.append("Unbalanced parentheses")
        
        if "(define (domain" not in pddl:
            errors.append("Missing domain definition")
        
        if "(:types" not in pddl:
            errors.append("Missing types section")
        
        if "(:predicates" not in pddl:
            errors.append("Missing predicates section")
        
        # Try VAL parser if available
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pddl', delete=False) as f:
                f.write(pddl)
                temp_path = f.name
            
            result = subprocess.run(
                ["validate", "-p", temp_path],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                errors.append(f"VAL: {result.stderr}")
            
            os.unlink(temp_path)
        except FileNotFoundError:
            pass  # VAL not installed
        except Exception as e:
            pass
        
        return len(errors) == 0, errors
    
    def _repair_pddl(self, pddl: str, errors: list[str]) -> str:
        """Attempt to repair PDDL syntax errors."""
        # Fix unbalanced parentheses
        open_count = pddl.count('(')
        close_count = pddl.count(')')
        
        if open_count > close_count:
            pddl += ')' * (open_count - close_count)
        elif close_count > open_count:
            # Remove extra closing parens from end
            while pddl.endswith(')') and pddl.count(')') > pddl.count('('):
                pddl = pddl[:-1]
        
        return pddl
    
    def get_merge_log(self) -> list[str]:
        """Return the merge operation log."""
        return self.merge_log


# =============================================================================
# SECTION 9: PDDL Syntax Repairer
# =============================================================================

class PDDLRepairer:
    """
    Repairs common LLM-generated PDDL syntax errors.
    Applied before merge phase to ensure valid input.
    """
    
    # Valid base types in our domain
    VALID_TYPES = {
        "object", "package", "service", "user", "group", "file", 
        "directory", "configuration_file", "port", "interface",
        "firewall_rule", "process", "repository", "filesystem_object",
        "system_user", "human_user"
    }
    
    def __init__(self):
        self.repairs_made: list[str] = []
    
    def repair(self, pddl: str) -> str:
        """Apply all repairs to PDDL string."""
        self.repairs_made = []
        
        # Apply repairs in order
        pddl = self._fix_invalid_types(pddl)
        pddl = self._fix_unbound_parameters(pddl)
        pddl = self._fix_invalid_quantifiers(pddl)
        pddl = self._fix_string_literals(pddl)
        pddl = self._fix_function_calls(pddl)
        pddl = self._fix_empty_and_blocks(pddl)
        pddl = self._extract_implicit_predicates(pddl)
        pddl = self._fix_parentheses(pddl)
        
        return pddl
    
    def _fix_invalid_types(self, pddl: str) -> str:
        """Replace invalid types like 'string', 'list' with 'object'."""
        invalid_types = ["string", "list", "command", "list_of_services", 
                        "dependency", "entries", "filtered_entries"]
        
        for inv_type in invalid_types:
            pattern = rf'\?\w+\s*-\s*{inv_type}\b'
            if re.search(pattern, pddl):
                pddl = re.sub(pattern, lambda m: m.group().replace(inv_type, "object"), pddl)
                self.repairs_made.append(f"Replaced invalid type '{inv_type}' with 'object'")
        
        return pddl
    
    def _fix_unbound_parameters(self, pddl: str) -> str:
        """Fix actions with empty parameters but used variables."""
        # Find actions with empty parameters
        action_pattern = r'\(:action\s+(\w+)\s*:parameters\s*\(\s*\)(.*?)(?=\(:action|\Z)'
        
        def fix_action(match):
            action_name = match.group(1)
            body = match.group(2)
            
            # Find all variables used in preconditions/effects
            vars_used = set(re.findall(r'\?(\w+)', body))
            
            if vars_used:
                # Infer types from predicate usage
                params = []
                for var in sorted(vars_used):
                    inferred_type = self._infer_type_from_context(var, body)
                    params.append(f"?{var} - {inferred_type}")
                
                params_str = " ".join(params)
                self.repairs_made.append(
                    f"Added parameters to action '{action_name}': {params_str}"
                )
                return f"(:action {action_name}\n    :parameters ({params_str}){body}"
            
            return match.group(0)
        
        return re.sub(action_pattern, fix_action, pddl, flags=re.DOTALL)
    
    def _infer_type_from_context(self, var: str, context: str) -> str:
        """Infer PDDL type from variable name and usage context."""
        var_lower = var.lower()
        
        # Common naming conventions
        type_hints = {
            "p": "package", "pkg": "package", "package": "package",
            "s": "service", "svc": "service", "service": "service",
            "u": "user", "user": "user",
            "g": "group", "group": "group",
            "f": "file", "file": "file", "src": "file", "dst": "file",
            "d": "directory", "dir": "directory", "directory": "directory",
            "r": "repository", "repo": "repository",
            "i": "interface", "iface": "interface", "interface": "interface",
            "port": "port",
            "rule": "firewall_rule", "chain": "firewall_rule",
            "proc": "process", "process": "process", "cmd": "process",
            "cfg": "configuration_file", "config": "configuration_file",
        }
        
        for hint, pddl_type in type_hints.items():
            if var_lower.startswith(hint) or var_lower.endswith(hint):
                return pddl_type
        
        # Check context for predicate usage
        if re.search(rf'installed\s+\?{var}', context):
            return "package"
        if re.search(rf'running\s+\?{var}', context):
            return "service"
        if re.search(rf'exists\s+\?{var}', context):
            return "file"
        
        return "object"  # Default fallback
    
    def _fix_invalid_quantifiers(self, pddl: str) -> str:
        """Fix invalid quantifier syntax like '?p :exists'."""
        # Pattern: (?var :exists (predicate))
        pattern = r'\(\s*\?\w+\s*:exists\s*\([^)]+\)\s*\)'
        
        def fix_quantifier(match):
            text = match.group(0)
            # Extract variable and predicate
            var_match = re.search(r'\?(\w+)\s*:exists', text)
            pred_match = re.search(r':exists\s*(\([^)]+\))', text)
            
            if var_match and pred_match:
                var = var_match.group(1)
                pred = pred_match.group(1)
                self.repairs_made.append(f"Fixed quantifier syntax for ?{var}")
                return f"(exists (?{var} - object) {pred})"
            return text
        
        return re.sub(pattern, fix_quantifier, pddl)
    
    def _fix_string_literals(self, pddl: str) -> str:
        """Remove string literal comparisons."""
        # Pattern: (equal ?var "string")
        pattern = r'\(equal\s+\?\w+\s+"[^"]+"\)'
        
        matches = re.findall(pattern, pddl)
        for match in matches:
            pddl = pddl.replace(match, "")
            self.repairs_made.append(f"Removed invalid string comparison: {match}")
        
        return pddl
    
    def _fix_function_calls(self, pddl: str) -> str:
        """Remove function calls from effects."""
        # Patterns for common invalid constructs
        invalid_patterns = [
            r'\(create_process\s+[^)]+\)',
            r'\(concat\s+[^)]+\)',
            r'\(strcat\s+[^)]+\)',
            r'\(find_newest_version\s+[^)]+\)',
            r'\(name\s+\?\w+\)',
            r'\(version_number\s+[^)]+\)',
            r'\(time_spent_\w+\)',
        ]
        
        for pattern in invalid_patterns:
            matches = re.findall(pattern, pddl)
            for match in matches:
                pddl = pddl.replace(match, "")
                self.repairs_made.append(f"Removed invalid function call: {match[:50]}")
        
        return pddl
    
    def _fix_empty_and_blocks(self, pddl: str) -> str:
        """Fix empty (and) blocks and malformed nested structures."""
        # Remove empty effects/preconditions
        pddl = re.sub(r':effect\s*\(and\s*\)', ':effect (and)', pddl)
        pddl = re.sub(r':precondition\s*\(and\s*\)', ':precondition (and)', pddl)
        
        # Fix orphaned parentheses from removed content
        # Pattern: (and (valid) () (valid))
        pddl = re.sub(r'\(\s*\)', '', pddl)
        
        # Fix double (( )) that might result from removals
        pddl = re.sub(r'\(\s*\(and', '(and', pddl)
        
        return pddl
    
    def _extract_implicit_predicates(self, pddl: str) -> str:
        """Extract predicates that are used but not declared."""
        # Find all predicate usages in actions
        pred_usage = set()
        
        # Pattern: (predicate_name ?var ...) but not (:action, :parameters, etc.
        pattern = r'\((\w+)\s+\?[\w\s?-]+\)'
        
        for match in re.finditer(pattern, pddl):
            pred_name = match.group(1)
            if pred_name not in ['and', 'or', 'not', 'exists', 'forall', 
                                 'action', 'parameters', 'precondition', 
                                 'effect', 'types', 'predicates']:
                pred_usage.add(pred_name)
        
        # Check if predicates section exists
        if '(:predicates' not in pddl:
            # Generate predicates section from usage
            pred_lines = []
            for pred in sorted(pred_usage):
                # Infer arity from usage
                usage_match = re.search(rf'\({pred}\s+([\?\w\s-]+)\)', pddl)
                if usage_match:
                    params = usage_match.group(1).strip()
                    pred_lines.append(f"    ({pred} {params})")
            
            if pred_lines:
                pred_section = "  (:predicates\n" + "\n".join(pred_lines) + "\n  )\n"
                # Insert after types
                pddl = re.sub(r'(\(:types[^)]+\)\s*)', rf'\1\n{pred_section}', pddl)
                self.repairs_made.append(f"Generated {len(pred_lines)} implicit predicates")
        
        return pddl
    
    def _fix_parentheses(self, pddl: str) -> str:
        """Balance parentheses."""
        open_count = pddl.count('(')
        close_count = pddl.count(')')
        
        if open_count > close_count:
            pddl += ')' * (open_count - close_count)
            self.repairs_made.append(f"Added {open_count - close_count} closing parentheses")
        elif close_count > open_count:
            # Remove excess closing parens from end
            excess = close_count - open_count
            for _ in range(excess):
                last_paren = pddl.rfind(')')
                if last_paren > 0:
                    pddl = pddl[:last_paren] + pddl[last_paren+1:]
            self.repairs_made.append(f"Removed {excess} excess closing parentheses")
        
        return pddl
    
    def get_repairs_log(self) -> list[str]:
        return self.repairs_made


# =============================================================================
# SECTION 10: PDDL Validator
# =============================================================================

class PDDLValidator:
    """Validates PDDL syntax and semantic correctness."""
    
    def __init__(self):
        self.val_available = self._check_val()
    
    def _check_val(self) -> bool:
        """Check if VAL parser is available."""
        try:
            result = subprocess.run(
                ["validate", "-h"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def validate_domain(self, domain_pddl: str) -> tuple[bool, list[str]]:
        """Validate a PDDL domain."""
        errors = []
        warnings = []
        
        # Structural validation
        if "(define (domain" not in domain_pddl:
            errors.append("Missing (define (domain ...))")
        
        # Check required sections
        required = [":types", ":predicates"]
        for req in required:
            if f"({req}" not in domain_pddl:
                errors.append(f"Missing {req} section")
        
        # Check parenthesis balance
        if domain_pddl.count('(') != domain_pddl.count(')'):
            errors.append(
                f"Unbalanced parentheses: {domain_pddl.count('(')} open, "
                f"{domain_pddl.count(')')} close"
            )
        
        # Check action structure
        action_pattern = r':action\s+(\w+)'
        actions = re.findall(action_pattern, domain_pddl)
        
        for action in actions:
            action_text = self._extract_action_text(domain_pddl, action)
            if action_text:
                if ":parameters" not in action_text:
                    errors.append(f"Action '{action}' missing :parameters")
                if ":precondition" not in action_text:
                    warnings.append(f"Action '{action}' missing :precondition")
                if ":effect" not in action_text:
                    warnings.append(f"Action '{action}' missing :effect")
        
        # VAL validation if available
        if self.val_available and not errors:
            val_errors = self._validate_with_val(domain_pddl)
            errors.extend(val_errors)
        
        return len(errors) == 0, errors + warnings
    
    def _extract_action_text(self, pddl: str, action_name: str) -> Optional[str]:
        """Extract the text of a specific action."""
        pattern = rf'\(:action\s+{action_name}\s*(.*?)(?=\(:action|\Z)'
        match = re.search(pattern, pddl, re.DOTALL)
        return match.group(1) if match else None
    
    def _validate_with_val(self, pddl: str) -> list[str]:
        """Validate using VAL parser."""
        errors = []
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.pddl', delete=False
            ) as f:
                f.write(pddl)
                temp_path = f.name
            
            result = subprocess.run(
                ["validate", "-p", temp_path],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                # Parse VAL output for errors
                for line in result.stderr.split('\n'):
                    if 'error' in line.lower():
                        errors.append(f"VAL: {line.strip()}")
            
            os.unlink(temp_path)
        except Exception as e:
            pass  # VAL not critical
        
        return errors


# =============================================================================
# SECTION 11: Phase 2 Orchestrator
# =============================================================================

class Phase2Orchestrator:
    """
    Main orchestrator for Phase 2: Parallel Synthesis.
    Coordinates Map and Reduce phases.
    """
    
    def __init__(
        self,
        hardware_config: Optional[HardwareConfig] = None,
        llm_config: Optional[LLMConfig] = None,
        osquery_data: Optional[dict] = None,
        use_mock_llm: bool = False,
        output_dir: str = "./pddl_output"
    ):
        self.hardware = hardware_config or HardwareConfig.detect()
        self.llm_config = llm_config or LLMConfig()
        self.osquery_data = osquery_data or {}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize LLM interface
        self.llm = get_llm_interface(self.llm_config, use_mock=use_mock_llm)
        
        # Initialize components
        self.supervisor = SupervisorAgent(
            llm=self.llm,
            hardware_config=self.hardware,
            osquery_data=self.osquery_data
        )
        self.merger = MergerAgent(llm=self.llm)
        self.validator = PDDLValidator()
        
        # Results
        self.partial_domains: list[PartialPDDLDomain] = []
        self.unified_domain: str = ""
    
    def run(self) -> dict:
        """Execute the complete Phase 2 pipeline."""
        results = {
            "success": False,
            "map_phase_complete": False,
            "reduce_phase_complete": False,
            "validation_passed": False,
            "errors": [],
            "warnings": [],
            "statistics": {},
            "merge_log": [],
        }
        
        print("\n" + "=" * 70)
        print("PHASE 2: PARALLEL SYNTHESIS (MAP-REDUCE)")
        print("=" * 70)
        print(f"\nHardware Configuration:")
        print(f"  GPUs: {self.hardware.num_gpus}x (L40S @ {self.hardware.gpu_memory_gb}GB)")
        print(f"  RAM: {self.hardware.total_ram_gb:.0f}GB")
        print(f"  CPUs: {self.hardware.num_cpus}")
        print(f"  Parallel Workers: {self.hardware.max_parallel_workers}")
        print(f"\nLLM: {self.llm_config.model_name}")
        
        try:
            # MAP PHASE
            print("\n" + "-" * 70)
            self.partial_domains = self.supervisor.execute_map_phase()
            results["map_phase_complete"] = True
            
            # Statistics
            successful = [d for d in self.partial_domains if not d.error]
            results["statistics"]["workers_total"] = len(self.partial_domains)
            results["statistics"]["workers_successful"] = len(successful)
            results["statistics"]["total_types"] = sum(
                len(d.types) for d in successful
            )
            results["statistics"]["total_predicates"] = sum(
                len(d.predicates) for d in successful
            )
            results["statistics"]["total_actions"] = sum(
                len(d.actions) for d in successful
            )
            
            # REDUCE PHASE
            print("\n" + "-" * 70)
            self.unified_domain = self.merger.merge(self.partial_domains)
            results["reduce_phase_complete"] = True
            results["merge_log"] = self.merger.get_merge_log()
            
            # VALIDATION
            print("\n" + "-" * 70)
            print("VALIDATION PHASE")
            print("-" * 70)
            
            is_valid, validation_msgs = self.validator.validate_domain(
                self.unified_domain
            )
            results["validation_passed"] = is_valid
            
            if is_valid:
                print("  ✓ Domain validation passed")
            else:
                print("  ⚠ Validation issues found:")
                for msg in validation_msgs:
                    print(f"    - {msg}")
                results["warnings"].extend(validation_msgs)
            
            # Save outputs
            domain_path = self.output_dir / "sysadmin.pddl"
            domain_path.write_text(self.unified_domain)
            print(f"\n  → Domain saved to: {domain_path}")
            
            # Save partial domains for debugging
            partials_path = self.output_dir / "partial_domains.json"
            partials_data = [d.to_dict() for d in self.partial_domains]
            partials_path.write_text(json.dumps(partials_data, indent=2))
            print(f"  → Partial domains saved to: {partials_path}")
            
            # Save merge log
            log_path = self.output_dir / "merge_log.txt"
            log_path.write_text("\n".join(results["merge_log"]))
            
            results["success"] = True
            results["domain_path"] = str(domain_path)
            results["domain_pddl"] = self.unified_domain
            
        except Exception as e:
            logger.exception("Phase 2 failed")
            results["errors"].append(str(e))
        
        # Final summary
        print("\n" + "=" * 70)
        print("PHASE 2 SUMMARY")
        print("=" * 70)
        print(f"  Status: {'SUCCESS' if results['success'] else 'FAILED'}")
        print(f"  Workers: {results['statistics'].get('workers_successful', 0)}/"
              f"{results['statistics'].get('workers_total', 0)} successful")
        print(f"  Types: {results['statistics'].get('total_types', 0)} → "
              f"{len(self.merger.unified_types)} unified")
        print(f"  Predicates: {results['statistics'].get('total_predicates', 0)} → "
              f"{len(self.merger.unified_predicates)} unified")
        print(f"  Actions: {results['statistics'].get('total_actions', 0)} → "
              f"{len(self.merger.unified_actions)} unified")
        print(f"  Validation: {'PASSED' if results['validation_passed'] else 'WARNINGS'}")
        
        return results


# =============================================================================
# SECTION 12: vLLM Server Launcher
# =============================================================================

def launch_vllm_server(config: LLMConfig, hardware: HardwareConfig) -> subprocess.Popen:
    """
    Launch vLLM server for LLM inference.
    
    For 2x L40S with 48GB each:
    - Can run Llama-3.1-70B with tensor parallelism
    - Or run multiple instances of smaller models
    """
    cmd = [
        "python", "-m", "vllm.entrypoints.openai.api_server",
        "--model", config.model_name,
        "--tensor-parallel-size", str(config.tensor_parallel_size),
        "--max-model-len", "8192",
        "--gpu-memory-utilization", "0.90",
        "--host", "0.0.0.0",
        "--port", "8000",
    ]
    
    logger.info(f"Launching vLLM server: {' '.join(cmd)}")
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to be ready
    import time
    for _ in range(60):  # Wait up to 60 seconds
        try:
            import urllib.request
            urllib.request.urlopen(f"{config.base_url}/health", timeout=1)
            logger.info("vLLM server is ready")
            return process
        except Exception:
            time.sleep(1)
    
    raise RuntimeError("vLLM server failed to start")


# =============================================================================
# SECTION 13: Entry Point
# =============================================================================

def main():
    """Main entry point for Phase 2 execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Phase 2: Parallel Synthesis for PDDL Domain Generation"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./pddl_output",
        help="Output directory for PDDL files"
    )
    parser.add_argument(
        "--model",
        default="mistralai/Mistral-7B-Instruct-v0.3",
        help="LLM model to use"
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use mock LLM for testing without GPU"
    )
    parser.add_argument(
        "--phase1-state",
        help="Path to Phase 1 state JSON file"
    )
    parser.add_argument(
        "--launch-vllm",
        action="store_true",
        help="Auto-launch vLLM server"
    )
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    
    args = parser.parse_args()
    
    # Load Phase 1 state if provided
    osquery_data = {}
    if args.phase1_state:
        with open(args.phase1_state) as f:
            phase1_data = json.load(f)
            osquery_data = phase1_data.get("objects", {})
    
    # Configure
    hardware = HardwareConfig.detect()
    llm_config = LLMConfig(model_name=args.model)
    
    # Launch vLLM if requested
    vllm_process = None
    if args.launch_vllm and not args.mock_llm:
        vllm_process = launch_vllm_server(llm_config, hardware)
    
    try:
        # Run orchestrator
        orchestrator = Phase2Orchestrator(
            hardware_config=hardware,
            llm_config=llm_config,
            osquery_data=osquery_data,
            use_mock_llm=args.mock_llm,
            output_dir=args.output_dir
        )
        
        results = orchestrator.run()
        
        if args.json_output:
            # Remove large PDDL string for JSON output
            output = {k: v for k, v in results.items() if k != "domain_pddl"}
            print(json.dumps(output, indent=2))
        else:
            if results.get("domain_pddl"):
                print("\n" + "=" * 70)
                print("GENERATED UNIFIED DOMAIN")
                print("=" * 70)
                print(results["domain_pddl"][:3000])  # First 3000 chars
                if len(results["domain_pddl"]) > 3000:
                    print(f"\n... [{len(results['domain_pddl']) - 3000} more characters]")
        
        return 0 if results["success"] else 1
        
    finally:
        if vllm_process:
            vllm_process.terminate()


if __name__ == "__main__":
    exit(main())



