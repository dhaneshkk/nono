# nono on AWS ECS Fargate

Run AI agents with OS-enforced capability sandboxing on Fargate. No privileged containers, no custom AMIs, no kernel modules.

## Why Fargate

Fargate uses Firecracker microVMs. Each task gets its own kernel. This eliminates the shared kernel concern that affects standard container deployments:

```
Firecracker microVM        kernel isolation (no shared kernel)
  Container (ECS task)     resource isolation (cgroups/namespaces)
    nono (Landlock)        capability isolation (this process can read X, not Y)
```

Containers don't know which files are credentials. nono does. Fargate doesn't know what your agent should be allowed to do. nono does. Each layer handles a different threat.

### Kernel compatibility

Fargate with Amazon Linux 2023 runs kernel 6.1+, which supports everything nono needs:

| Feature | Required kernel | Fargate AL2023 |
|---------|----------------|----------------|
| Landlock filesystem isolation | 5.13+ | Yes |
| Landlock TCP network filtering | 5.19+ (ABI v4) | Yes |
| seccomp user notification | 5.0+ | Yes |
| Atomic fd injection (`SECCOMP_ADDFD_FLAG_SEND`) | 5.14+ | Yes |
| `SECCOMP_FILTER_FLAG_WAIT_KILLABLE` (Go compat) | 5.19+ | Yes |

Landlock is an unprivileged operation. No `CAP_SYS_ADMIN`, no privileged mode, no special task role permissions.

The seccomp-notify primitives (transparent capability expansion) require either `CAP_SYS_ADMIN` or `no_new_privs`. Fargate's container runtime sets `no_new_privs` by default, so this works without elevated capabilities.

## Prerequisites

- AWS CLI v2 configured with credentials (`aws configure`)
- Docker installed and running
- An existing VPC with at least one public subnet (for ECR image pull)

## Quick start

```bash
cd examples/ecs-fargate

export AWS_REGION=us-east-1
export VPC_ID=vpc-xxxxxxxx
export SUBNET_ID=subnet-xxxxxxxx

./deploy.sh
```

The script creates everything needed: ECR repository, IAM execution role, CloudWatch log group, security group, ECS cluster, task definition. Then it runs the task and prints log-tailing instructions.

Watch the output:

```bash
aws logs tail /ecs/nono-sandbox-poc --follow --region us-east-1
```

Clean up:

```bash
./deploy.sh cleanup
```

## What the PoC demonstrates

The test script (`test-sandbox.sh`) runs inside the Fargate container and exercises five checks:

**1. Environment** - Prints kernel version and nono version. Confirms you're running on a 6.1+ kernel.

**2. Sandbox support** - `nono setup --check-only` verifies Landlock is available and reports the ABI version.

**3. Filesystem isolation** - Creates a workspace directory and a secret file outside it. Runs a sandboxed process with `--allow /home/agent/workspace`. Reads inside the allowed path succeed. Reads outside it get EPERM.

**4. Network blocking** - Runs with `--net-block`. Outbound TCP connections are denied by Landlock's network filtering.

**5. Dry-run policy** - `--dry-run` prints the full policy summary showing exactly what would be enforced.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build: Rust 1.77 builder, Amazon Linux 2023 runtime |
| `task-definition.json` | Fargate task definition (512 CPU / 1 GB memory) |
| `deploy.sh` | AWS infrastructure setup + task execution |
| `test-sandbox.sh` | Sandbox verification script (container entrypoint) |

## Container image

The Dockerfile uses a two-stage build:

**Builder stage** (`rust:1.77-slim-bookworm`): Compiles `nono-cli` from source. Needs `libdbus-1-dev` for the keyring crate's D-Bus dependency.

**Runtime stage** (`amazonlinux:2023-minimal`): Contains only the stripped `nono` binary and minimal runtime libraries. Runs as a non-root `agent` user. The final image is small (~50 MB).

To build locally (for testing before pushing to ECR):

```bash
# From the workspace root
docker build -t nono-fargate -f examples/ecs-fargate/Dockerfile .
docker run --rm nono-fargate
```

Note: Landlock is a Linux kernel feature. If you build and run on macOS Docker Desktop, the test will report Landlock as unsupported (Docker Desktop uses a Linux VM, but its kernel may not have Landlock enabled). The test is designed for Fargate where the kernel is guaranteed to support it.

## Running a real agent

Replace the default CMD in your task definition with your agent command wrapped by nono.

### Claude Code

```json
"command": [
    "nono", "run",
    "--profile", "claude-code",
    "--allow", "/home/agent/workspace",
    "--supervised",
    "--", "claude"
]
```

The `--supervised` flag enables the fork-first execution model where the parent stays unsandboxed for diagnostics and (when wired up) transparent capability expansion via seccomp-notify.

### Custom agent

```json
"command": [
    "nono", "run",
    "--allow", "/home/agent/workspace",
    "--read", "/opt/agent/config",
    "--net-block",
    "--", "python", "/opt/agent/main.py"
]
```

### Secrets

Use ECS Secrets Manager integration instead of the system keyring. There's no D-Bus secret service inside a container. Add secrets to your task definition:

```json
"secrets": [
    {
        "name": "ANTHROPIC_API_KEY",
        "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789:secret:anthropic-key"
    }
]
```

The secret is injected as an environment variable. nono's sandbox does not restrict environment variable reads, so the agent process receives the key normally. If you need credential isolation (agent never sees the key), the proxy architecture described in `DESIGN-library.md` is the path forward.

## Task definition options

### Architecture

The task definition defaults to `X86_64`. For Graviton (ARM64) instances, change `runtimePlatform`:

```json
"runtimePlatform": {
    "cpuArchitecture": "ARM64",
    "operatingSystemFamily": "LINUX"
}
```

nono's seccomp-notify BPF filter includes syscall numbers for both x86_64 and aarch64. The Dockerfile builds for the host architecture. For cross-architecture builds, use Docker buildx:

```bash
docker buildx build --platform linux/arm64 -t nono-fargate-arm64 -f examples/ecs-fargate/Dockerfile .
```

### Resource sizing

The PoC uses minimal resources (512 CPU / 1 GB memory). For real agent workloads:

| Workload | CPU | Memory |
|----------|-----|--------|
| Lightweight script agent | 256 | 512 |
| Claude Code session | 1024 | 2048 |
| Multi-tool agent with large context | 2048 | 4096 |

nono itself adds negligible overhead. The sandbox is applied once at startup (a single syscall). Landlock enforcement is in-kernel with zero per-operation overhead for allowed paths. seccomp-notify adds ~3-10 microseconds per trapped `openat` call (two context switches), but only for paths that need dynamic approval.

### Logging

The task definition sends container stdout/stderr to CloudWatch Logs at `/ecs/nono-sandbox-poc`. nono's diagnostic output (the `[nono]` prefixed lines on sandbox errors) appears in these logs.

For structured logging, set the `NONO_LOG` environment variable:

```json
"environment": [
    {"name": "NONO_LOG", "value": "debug"}
]
```

## Security posture

### What nono enforces on Fargate

- **Filesystem**: Strict allow-list via Landlock. The agent process can only access paths explicitly granted. Everything else returns EPERM.
- **Network**: TCP bind/connect filtering via Landlock ABI v4+. `--net-block` denies all outbound TCP.
- **Commands**: Dangerous commands (`rm`, `dd`, `chmod`, etc.) blocked by default via the profile's deny list.
- **Ptrace**: `PR_SET_DUMPABLE(0)` prevents the sandboxed child from attaching to the supervisor parent.

### What Fargate enforces

- **Kernel isolation**: Firecracker microVM per task. A kernel exploit in one task cannot affect another.
- **Resource isolation**: CPU/memory limits enforced by cgroups.
- **Network isolation**: VPC security groups control inbound/outbound at the infrastructure level.
- **IAM**: Task roles scope AWS API access. The execution role only needs ECR pull and CloudWatch Logs.

### Combined threat model

| Attack | Fargate alone | nono alone | Both |
|--------|--------------|-----------|------|
| Agent reads `~/.ssh/id_rsa` | Possible (same container filesystem) | Blocked (not in allow-list) | Blocked |
| Agent exfiltrates data over HTTPS | Possible (outbound allowed) | Blocked (`--net-block`) | Blocked |
| Agent `rm -rf /` | Possible (container writable) | Blocked (command deny-list + write scope) | Blocked |
| Kernel exploit escapes container | Blocked (Firecracker VM boundary) | Not addressed (same kernel) | Blocked |
| Agent reads other task's files | Blocked (VM isolation) | N/A (different process) | Blocked |

The combination eliminates residual risk from both sides. Fargate handles infrastructure-level threats that nono can't (kernel exploits). nono handles application-level threats that Fargate can't (credential access within the same container).

## Troubleshooting

### Landlock not supported

If `nono setup --check-only` reports Landlock as unavailable:

1. Check the kernel version: `uname -r`. Must be 5.13+ with `CONFIG_SECURITY_LANDLOCK=y`.
2. Fargate platform version must be `1.4.0` (the default and latest). Older versions may run older kernels.
3. Some AWS regions may lag on kernel updates. Try `us-east-1` or `us-west-2`.

### seccomp-notify fails

If `install_seccomp_notify()` returns EACCES:

1. Verify `no_new_privs` is set: `cat /proc/self/status | grep NoNewPrivs`. Should be `1`.
2. Check if the container runtime's seccomp profile allows `seccomp()`. Standard containerd profiles do.
3. This only affects `--supervised` mode with transparent capability expansion. Basic Landlock sandboxing works without seccomp-notify.

### Task fails to start

1. Check CloudWatch Logs: `aws logs tail /ecs/nono-sandbox-poc --follow`
2. Check task status: `aws ecs describe-tasks --cluster nono-sandbox-poc --tasks <TASK_ARN> --query 'tasks[0].{status:lastStatus,reason:stoppedReason}'`
3. Common causes: ECR image pull failure (check execution role has `ecr:GetDownloadUrlForLayer`), subnet has no internet gateway (needed for ECR pull with public IP).
