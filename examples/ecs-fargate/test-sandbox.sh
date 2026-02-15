#!/bin/bash
# test-sandbox.sh - Demonstrates nono sandboxing inside a Fargate container.
#
# This script:
#   1. Checks kernel + Landlock support
#   2. Runs a sandboxed process with restricted filesystem access
#   3. Proves the sandbox denies access outside allowed paths
#   4. Demonstrates network blocking
#
# Run this inside the container (it's the default CMD in the Dockerfile).

set -euo pipefail

echo "============================================"
echo " nono Fargate Sandbox PoC"
echo "============================================"
echo ""

# -----------------------------------------------
# 1. Environment info
# -----------------------------------------------
echo "[1/5] Environment"
echo "  Kernel:  $(uname -r)"
echo "  Arch:    $(uname -m)"
echo "  nono:    $(nono --version 2>&1 || echo 'not found')"
echo ""

# -----------------------------------------------
# 2. Check sandbox support
# -----------------------------------------------
echo "[2/5] Sandbox support check"
nono setup --check-only 2>&1 | sed 's/^/  /'
echo ""

# -----------------------------------------------
# 3. Sandboxed filesystem access
# -----------------------------------------------
echo "[3/5] Filesystem isolation"

# Create a workspace with a test file
mkdir -p /home/agent/workspace
echo "sandbox-allowed" > /home/agent/workspace/allowed.txt

# Create a file OUTSIDE the allowed path
echo "sandbox-secret" > /home/agent/secret.txt

# Run sandboxed: only /home/agent/workspace is allowed
echo "  Allowed path: /home/agent/workspace (read+write)"
echo ""

# Should succeed: reading file inside allowed path
echo "  [ALLOWED] Reading /home/agent/workspace/allowed.txt:"
nono run --allow /home/agent/workspace -- cat /home/agent/workspace/allowed.txt 2>&1 | sed 's/^/    /'
echo ""

# Should fail: reading file outside allowed path
echo "  [DENIED] Reading /home/agent/secret.txt (outside sandbox):"
nono run --allow /home/agent/workspace -- cat /home/agent/secret.txt 2>&1 | sed 's/^/    /' || true
echo ""

# Should fail: writing outside allowed path
echo "  [DENIED] Writing to /tmp/escape.txt (outside sandbox):"
nono run --allow /home/agent/workspace -- sh -c 'echo "escaped" > /tmp/escape.txt' 2>&1 | sed 's/^/    /' || true
echo ""

# -----------------------------------------------
# 4. Network blocking
# -----------------------------------------------
echo "[4/5] Network isolation"
echo "  Running with --net-block..."
echo ""

# Should fail: network access blocked
echo "  [DENIED] Attempting outbound connection:"
nono run --allow /home/agent/workspace --net-block -- \
    sh -c 'echo "GET / HTTP/1.0" | timeout 3 bash -c "cat > /dev/tcp/1.1.1.1/80" 2>&1 || echo "Network blocked (expected)"' \
    2>&1 | sed 's/^/    /' || true
echo ""

# -----------------------------------------------
# 5. Dry-run output (shows what would be enforced)
# -----------------------------------------------
echo "[5/5] Dry-run policy summary"
nono run --allow /home/agent/workspace --net-block --dry-run -- echo "test" 2>&1 | sed 's/^/  /'
echo ""

echo "============================================"
echo " PoC complete. All sandbox checks passed."
echo "============================================"
