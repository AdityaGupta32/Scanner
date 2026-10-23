"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — Dynamic Sandbox Orchestrator                          ║
║  Manages lifecycle of ephemeral container creation & destruction    ║
║  Zone: net_red (manages targets) + net_blue (API access)           ║
╚══════════════════════════════════════════════════════════════════════╝

Responsibilities:
  1. Create sandboxed containers for scan targets on-demand
  2. Enforce resource limits (CPU, memory, network)
  3. Auto-destroy containers after TTL expiry
  4. Track active sandboxes with health monitoring
  5. Prevent sandbox escape via strict isolation
"""

import os
import uuid
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

# ── Configuration ────────────────────────────────────────────────────
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "infrastructure_net_red")
MAX_SANDBOXES = int(os.environ.get("MAX_SANDBOXES", "10"))
SANDBOX_TTL_SECONDS = int(os.environ.get("SANDBOX_TTL_SECONDS", "600"))
SANDBOX_MEMORY_LIMIT = os.environ.get("SANDBOX_MEMORY_LIMIT", "256m")
SANDBOX_CPU_LIMIT = float(os.environ.get("SANDBOX_CPU_LIMIT", "0.5"))
CLEANUP_INTERVAL_SECONDS = 30

# ── Sandbox Registry (in-memory) ────────────────────────────────────
sandbox_registry: Dict[str, dict] = {}

# ── Docker Client ────────────────────────────────────────────────────
docker_client = None

def get_docker_client():
    """Lazy-initialize Docker client."""
    global docker_client
    if docker_client is None:
        try:
            import docker
            docker_client = docker.from_env()
            docker_client.ping()
            print("[+] Docker client connected successfully")
        except ImportError:
            print("[!] Docker SDK not installed — running in MOCK mode")
            docker_client = "mock"
        except Exception as e:
            print(f"[!] Docker connection failed: {e} — running in MOCK mode")
            docker_client = "mock"
    return docker_client


# ── Pydantic Models ──────────────────────────────────────────────────
class SandboxCreateRequest(BaseModel):
    """Request to create a new sandbox."""
    image: str = Field(
        default="versescan/vulnerable-app:latest",
        description="Docker image to run in the sandbox"
    )
    name: Optional[str] = Field(
        default=None,
        description="Optional human-readable name for the sandbox"
    )
    port: int = Field(
        default=8081,
        description="Internal port the target app listens on"
    )
    env_vars: Dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables to inject"
    )
    memory_limit: str = Field(
        default=SANDBOX_MEMORY_LIMIT,
        description="Memory limit (e.g., '256m', '512m')"
    )
    cpu_limit: float = Field(
        default=SANDBOX_CPU_LIMIT,
        description="CPU limit (e.g., 0.5 = half a core)"
    )
    ttl_seconds: int = Field(
        default=SANDBOX_TTL_SECONDS,
        description="Time-to-live in seconds before auto-destruction"
    )
    custom_dockerfile: Optional[str] = Field(
        default=None,
        description="Optional inline Dockerfile content for custom targets"
    )
    scan_id: Optional[str] = Field(
        default=None,
        description="Associated scan ID for tracking"
    )

class SandboxResponse(BaseModel):
    """Sandbox information response."""
    sandbox_id: str
    status: str
    container_name: str
    target_url: str
    internal_ip: Optional[str] = None
    port: int
    created_at: str
    expires_at: str
    memory_limit: str
    cpu_limit: float
    image: str
    scan_id: Optional[str] = None

class SandboxListResponse(BaseModel):
    """List of active sandboxes."""
    total: int
    max_allowed: int
    sandboxes: List[SandboxResponse]


# ── Lifecycle Functions ──────────────────────────────────────────────

async def create_sandbox_container(request: SandboxCreateRequest) -> dict:
    """
    Create an isolated sandbox container on net_red.

    Security constraints:
      - No network access except from scanner (enforced by NetworkPolicy/iptables)
      - Resource limits (memory, CPU)
      - Read-only filesystem where possible
      - No privilege escalation
      - Auto-expiry via TTL
    """
    client = get_docker_client()
    sandbox_id = str(uuid.uuid4())[:12]
    container_name = f"vs-sandbox-{request.name or sandbox_id}"
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=request.ttl_seconds)

    # Allocate a dynamic port in the sandbox range (8082-8099)
    used_ports = {s["port"] for s in sandbox_registry.values()}
    available_port = request.port
    for p in range(8082, 8100):
        if p not in used_ports:
            available_port = p
            break

    sandbox_info = {
        "sandbox_id": sandbox_id,
        "container_name": container_name,
        "container_id": None,
        "status": "creating",
        "image": request.image,
        "port": available_port,
        "internal_ip": None,
        "target_url": f"http://{container_name}:{available_port}",
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": request.ttl_seconds,
        "memory_limit": request.memory_limit,
        "cpu_limit": request.cpu_limit,
        "scan_id": request.scan_id,
        "env_vars": request.env_vars,
    }

    if client == "mock":
        # Mock mode — simulate container creation
        sandbox_info["status"] = "running"
        sandbox_info["container_id"] = f"mock-{sandbox_id}"
        sandbox_info["internal_ip"] = f"172.30.0.{30 + len(sandbox_registry)}"
        sandbox_info["target_url"] = f"http://{sandbox_info['internal_ip']}:{available_port}"
        sandbox_registry[sandbox_id] = sandbox_info
        print(f"[MOCK] Created sandbox {sandbox_id}: {container_name}")
        return sandbox_info

    try:
        import docker

        # Prepare environment
        env = {
            "TARGET_PORT": str(available_port),
            "SANDBOX_ID": sandbox_id,
            **request.env_vars,
        }

        # Security options
        security_opts = [
            "no-new-privileges:true",
        ]

        # Create container with strict isolation
        container = client.containers.run(
            image=request.image,
            name=container_name,
            hostname=container_name,
            detach=True,
            environment=env,
            network=SANDBOX_NETWORK,
            mem_limit=request.memory_limit,
            nano_cpus=int(request.cpu_limit * 1e9),
            security_opt=security_opts,
            # Drop all capabilities except minimal set
            cap_drop=["ALL"],
            cap_add=["NET_BIND_SERVICE"],
            # Read-only root filesystem (app writes to tmpfs)
            read_only=True,
            tmpfs={"/tmp": "size=50M,mode=1777"},
            # No privilege escalation
            privileged=False,
            # Labels for identification and cleanup
            labels={
                "versescan.sandbox": "true",
                "versescan.sandbox_id": sandbox_id,
                "versescan.zone": "red",
                "versescan.role": "target",
                "versescan.scan_id": request.scan_id or "",
                "versescan.expires_at": expires_at.isoformat(),
            },
            # Auto-remove on stop (defense in depth)
            auto_remove=False,
        )

        # Get container IP on the sandbox network
        container.reload()
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        internal_ip = None
        for net_name, net_info in networks.items():
            if "red" in net_name.lower() or net_name == SANDBOX_NETWORK:
                internal_ip = net_info.get("IPAddress")
                break

        sandbox_info["container_id"] = container.id[:12]
        sandbox_info["internal_ip"] = internal_ip
        sandbox_info["status"] = "running"
        sandbox_info["target_url"] = f"http://{internal_ip or container_name}:{available_port}"

        sandbox_registry[sandbox_id] = sandbox_info
        print(f"[+] Sandbox created: {sandbox_id} ({container_name}) -> {sandbox_info['target_url']}")

        return sandbox_info

    except docker.errors.ImageNotFound:
        sandbox_info["status"] = "error"
        sandbox_info["error"] = f"Image not found: {request.image}"
        sandbox_registry[sandbox_id] = sandbox_info
        raise HTTPException(status_code=404, detail=f"Image not found: {request.image}")

    except docker.errors.APIError as e:
        sandbox_info["status"] = "error"
        sandbox_info["error"] = str(e)
        sandbox_registry[sandbox_id] = sandbox_info
        raise HTTPException(status_code=500, detail=f"Docker API error: {e}")

    except Exception as e:
        sandbox_info["status"] = "error"
        sandbox_info["error"] = str(e)
        sandbox_registry[sandbox_id] = sandbox_info
        raise HTTPException(status_code=500, detail=f"Sandbox creation failed: {e}")


async def destroy_sandbox(sandbox_id: str, reason: str = "manual") -> dict:
    """
    Destroy a sandbox container and clean up resources.
    """
    if sandbox_id not in sandbox_registry:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {sandbox_id}")

    info = sandbox_registry[sandbox_id]
    client = get_docker_client()

    if client == "mock":
        info["status"] = "destroyed"
        info["destroyed_at"] = datetime.utcnow().isoformat()
        info["destroy_reason"] = reason
        del sandbox_registry[sandbox_id]
        print(f"[MOCK] Destroyed sandbox {sandbox_id} (reason: {reason})")
        return info

    try:
        container = client.containers.get(info["container_name"])
        # Force stop (kill) — don't wait for graceful shutdown
        container.stop(timeout=5)
        container.remove(force=True)
        print(f"[+] Sandbox destroyed: {sandbox_id} (reason: {reason})")
    except Exception as e:
        print(f"[!] Error destroying sandbox {sandbox_id}: {e}")
        # Try force removal
        try:
            container = client.containers.get(info["container_name"])
            container.remove(force=True)
        except Exception:
            pass

    info["status"] = "destroyed"
    info["destroyed_at"] = datetime.utcnow().isoformat()
    info["destroy_reason"] = reason
    del sandbox_registry[sandbox_id]
    return info


async def cleanup_expired_sandboxes():
    """Background task: destroy sandboxes that have exceeded their TTL."""
    while True:
        try:
            now = datetime.utcnow()
            expired_ids = []

            for sid, info in sandbox_registry.items():
                expires_at = datetime.fromisoformat(info["expires_at"])
                if now > expires_at and info["status"] == "running":
                    expired_ids.append(sid)

            for sid in expired_ids:
                try:
                    await destroy_sandbox(sid, reason="ttl_expired")
                    print(f"[CLEANUP] Auto-destroyed expired sandbox: {sid}")
                except Exception as e:
                    print(f"[!] Cleanup error for {sid}: {e}")

            # Also clean up orphaned Docker containers with our labels
            client = get_docker_client()
            if client != "mock":
                try:
                    import docker
                    containers = client.containers.list(
                        filters={"label": "versescan.sandbox=true"},
                        all=True
                    )
                    known_containers = {
                        info.get("container_name") for info in sandbox_registry.values()
                    }
                    for container in containers:
                        if container.name not in known_containers:
                            try:
                                container.remove(force=True)
                                print(f"[CLEANUP] Removed orphaned container: {container.name}")
                            except Exception:
                                pass
                except Exception:
                    pass

        except Exception as e:
            print(f"[!] Cleanup loop error: {e}")

        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


async def get_sandbox_health(sandbox_id: str) -> dict:
    """Check health status of a sandbox container."""
    if sandbox_id not in sandbox_registry:
        return {"sandbox_id": sandbox_id, "healthy": False, "error": "not found"}

    info = sandbox_registry[sandbox_id]
    client = get_docker_client()

    if client == "mock":
        return {
            "sandbox_id": sandbox_id,
            "healthy": info["status"] == "running",
            "status": info["status"],
            "uptime_seconds": int(
                (datetime.utcnow() - datetime.fromisoformat(info["created_at"])).total_seconds()
            ),
            "ttl_remaining": int(
                (datetime.fromisoformat(info["expires_at"]) - datetime.utcnow()).total_seconds()
            ),
        }

    try:
        container = client.containers.get(info["container_name"])
        container.reload()
        state = container.attrs.get("State", {})

        return {
            "sandbox_id": sandbox_id,
            "healthy": state.get("Running", False),
            "status": state.get("Status", "unknown"),
            "pid": state.get("Pid", 0),
            "uptime_seconds": int(
                (datetime.utcnow() - datetime.fromisoformat(info["created_at"])).total_seconds()
            ),
            "ttl_remaining": int(
                (datetime.fromisoformat(info["expires_at"]) - datetime.utcnow()).total_seconds()
            ),
            "memory_usage": container.stats(stream=False).get("memory_stats", {}),
        }
    except Exception as e:
        return {
            "sandbox_id": sandbox_id,
            "healthy": False,
            "error": str(e),
        }


# ── FastAPI App ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background cleanup on startup, teardown on shutdown."""
    cleanup_task = asyncio.create_task(cleanup_expired_sandboxes())
    print(f"[+] Sandbox Orchestrator started (max={MAX_SANDBOXES}, ttl={SANDBOX_TTL_SECONDS}s)")
    yield
    # Shutdown: destroy all remaining sandboxes
    cleanup_task.cancel()
    for sid in list(sandbox_registry.keys()):
        try:
            await destroy_sandbox(sid, reason="shutdown")
        except Exception:
            pass
    print("[*] All sandboxes destroyed on shutdown")


app = FastAPI(
    title="VerseScan Sandbox Orchestrator",
    version="1.0",
    description="Dynamic container lifecycle management for isolated scan targets",
    lifespan=lifespan,
)


# ── Routes ───────────────────────────────────────────────────────────

@app.post("/sandbox", response_model=SandboxResponse)
async def create_sandbox(request: SandboxCreateRequest):
    """
    Create a new sandboxed container for scanning.

    The container is:
    - Placed on net_red (isolated from blue/llm zones)
    - Resource-limited (CPU + memory)
    - Auto-destroyed after TTL expires
    - Running with dropped capabilities (no-new-privileges)
    """
    # Check sandbox limit
    active_count = sum(1 for s in sandbox_registry.values() if s["status"] == "running")
    if active_count >= MAX_SANDBOXES:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum sandbox limit reached ({MAX_SANDBOXES}). Destroy existing sandboxes first."
        )

    result = await create_sandbox_container(request)

    return SandboxResponse(
        sandbox_id=result["sandbox_id"],
        status=result["status"],
        container_name=result["container_name"],
        target_url=result["target_url"],
        internal_ip=result.get("internal_ip"),
        port=result["port"],
        created_at=result["created_at"],
        expires_at=result["expires_at"],
        memory_limit=result["memory_limit"],
        cpu_limit=result["cpu_limit"],
        image=result["image"],
        scan_id=result.get("scan_id"),
    )


@app.delete("/sandbox/{sandbox_id}")
async def delete_sandbox(sandbox_id: str):
    """Destroy a sandbox container immediately."""
    result = await destroy_sandbox(sandbox_id, reason="api_request")
    return {"message": f"Sandbox {sandbox_id} destroyed", "details": result}


@app.get("/sandbox/{sandbox_id}", response_model=SandboxResponse)
async def get_sandbox(sandbox_id: str):
    """Get information about a specific sandbox."""
    if sandbox_id not in sandbox_registry:
        raise HTTPException(status_code=404, detail="Sandbox not found")

    info = sandbox_registry[sandbox_id]
    return SandboxResponse(
        sandbox_id=info["sandbox_id"],
        status=info["status"],
        container_name=info["container_name"],
        target_url=info["target_url"],
        internal_ip=info.get("internal_ip"),
        port=info["port"],
        created_at=info["created_at"],
        expires_at=info["expires_at"],
        memory_limit=info["memory_limit"],
        cpu_limit=info["cpu_limit"],
        image=info["image"],
        scan_id=info.get("scan_id"),
    )


@app.get("/sandbox/{sandbox_id}/health")
async def sandbox_health(sandbox_id: str):
    """Check health status of a sandbox."""
    return await get_sandbox_health(sandbox_id)


@app.get("/sandboxes", response_model=SandboxListResponse)
async def list_sandboxes():
    """List all active sandboxes."""
    sandboxes = [
        SandboxResponse(
            sandbox_id=info["sandbox_id"],
            status=info["status"],
            container_name=info["container_name"],
            target_url=info["target_url"],
            internal_ip=info.get("internal_ip"),
            port=info["port"],
            created_at=info["created_at"],
            expires_at=info["expires_at"],
            memory_limit=info["memory_limit"],
            cpu_limit=info["cpu_limit"],
            image=info["image"],
            scan_id=info.get("scan_id"),
        )
        for info in sandbox_registry.values()
    ]

    return SandboxListResponse(
        total=len(sandboxes),
        max_allowed=MAX_SANDBOXES,
        sandboxes=sandboxes,
    )


@app.post("/sandbox/{sandbox_id}/extend")
async def extend_sandbox_ttl(sandbox_id: str, extra_seconds: int = 300):
    """Extend a sandbox's TTL by additional seconds."""
    if sandbox_id not in sandbox_registry:
        raise HTTPException(status_code=404, detail="Sandbox not found")

    info = sandbox_registry[sandbox_id]
    current_expiry = datetime.fromisoformat(info["expires_at"])
    new_expiry = current_expiry + timedelta(seconds=extra_seconds)
    info["expires_at"] = new_expiry.isoformat()

    return {
        "sandbox_id": sandbox_id,
        "new_expires_at": new_expiry.isoformat(),
        "extended_by_seconds": extra_seconds,
    }


@app.post("/sandbox/destroy-all")
async def destroy_all_sandboxes():
    """Emergency: destroy all active sandboxes."""
    destroyed = []
    for sid in list(sandbox_registry.keys()):
        try:
            result = await destroy_sandbox(sid, reason="destroy_all")
            destroyed.append(sid)
        except Exception as e:
            print(f"[!] Failed to destroy {sid}: {e}")

    return {
        "message": f"Destroyed {len(destroyed)} sandboxes",
        "destroyed_ids": destroyed,
    }


@app.get("/health")
async def health_check():
    """Orchestrator health check."""
    client = get_docker_client()
    docker_connected = client != "mock"

    if docker_connected:
        try:
            client.ping()
        except Exception:
            docker_connected = False

    active_count = sum(1 for s in sandbox_registry.values() if s["status"] == "running")

    return {
        "status": "healthy",
        "service": "sandbox-orchestrator",
        "docker_connected": docker_connected,
        "active_sandboxes": active_count,
        "max_sandboxes": MAX_SANDBOXES,
        "sandbox_ttl_seconds": SANDBOX_TTL_SECONDS,
        "cleanup_interval_seconds": CLEANUP_INTERVAL_SECONDS,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/")
async def root():
    return {
        "service": "VerseScan Sandbox Orchestrator",
        "version": "1.0",
        "zone": "net_red + net_blue",
        "description": "Dynamic container lifecycle management",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
