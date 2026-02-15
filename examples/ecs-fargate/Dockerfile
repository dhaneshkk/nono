# nono on ECS Fargate - Multi-stage build
#
# Builds nono from source and packages it into a minimal Amazon Linux 2023
# image suitable for Fargate tasks.
#
# Fargate with AL2023 provides kernel 6.1+ which supports:
#   - Landlock LSM (filesystem + network isolation)
#   - seccomp user notification (transparent capability expansion)
#
# No CAP_SYS_ADMIN or privileged mode required.

# ---------------------------------------------------------------------------
# Stage 1: Build nono from source
# ---------------------------------------------------------------------------
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build only the CLI binary (includes library as dependency)
RUN cargo build --release -p nono-cli \
    && strip target/release/nono

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# dbus-libs: runtime dependency for keyring crate (optional - can skip if
# secrets come purely from ECS Secrets Manager / environment variables)
RUN if command -v microdnf >/dev/null 2>&1; then \
      microdnf install -y dbus-libs shadow-utils && microdnf clean all; \
    else \
      dnf install -y dbus-libs shadow-utils && dnf clean all; \
    fi

COPY --from=builder /build/target/release/nono /usr/local/bin/nono

# Smoke test: binary loads and prints version
RUN nono --version

# Create a non-root user for the agent workload.
# nono's sandbox applies to this user's process.
RUN useradd --create-home --shell /bin/bash agent
USER agent
WORKDIR /home/agent

# Copy the sandbox test script (for the PoC)
COPY --chown=agent:agent examples/ecs-fargate/test-sandbox.sh /home/agent/test-sandbox.sh
RUN chmod +x /home/agent/test-sandbox.sh

# Default: run the sandbox test. Override CMD in your task definition
# to run your actual agent (e.g., ["nono", "run", "--profile", "claude-code", "--", "claude"])
CMD ["/home/agent/test-sandbox.sh"]
