#!/bin/bash
# deploy.sh - Deploy the nono sandbox PoC to AWS ECS Fargate.
#
# Prerequisites:
#   - AWS CLI v2 configured with credentials (aws configure)
#   - Docker installed and running
#   - An existing VPC with at least one public subnet
#
# Usage:
#   # Set required variables
#   export AWS_REGION=us-east-1
#   export VPC_ID=vpc-xxxxxxxx
#   export SUBNET_ID=subnet-xxxxxxxx
#
#   # Deploy (creates ECR repo, ECS cluster, task def, runs task)
#   ./deploy.sh
#
#   # Tear down
#   ./deploy.sh cleanup

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override with environment variables)
# ---------------------------------------------------------------------------
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
CLUSTER_NAME="${CLUSTER_NAME:-nono-sandbox-poc}"
ECR_REPO="${ECR_REPO:-nono-sandbox-poc}"
TASK_FAMILY="nono-sandbox-poc"
LOG_GROUP="/ecs/nono-sandbox-poc"

# These MUST be set by the user
VPC_ID="${VPC_ID:?Set VPC_ID to your VPC (e.g., vpc-abc123)}"
SUBNET_ID="${SUBNET_ID:?Set SUBNET_ID to a public subnet in your VPC}"

# Guard against accidentally using an Availability Zone (e.g., eu-west-2a)
# where a region is required (e.g., eu-west-2).
if [[ "${AWS_REGION}" =~ [0-9][a-z]$ ]]; then
    SUGGESTED_REGION="${AWS_REGION::-1}"
    echo "Error: AWS_REGION appears to be an Availability Zone: ${AWS_REGION}" >&2
    echo "Use a region like '${SUGGESTED_REGION}' instead (no trailing letter)." >&2
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --region "${AWS_REGION}" --query Account --output text)
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"
NONO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "Account:  ${AWS_ACCOUNT_ID}"
echo "Region:   ${AWS_REGION}"
echo "VPC:      ${VPC_ID}"
echo "Subnet:   ${SUBNET_ID}"
echo "ECR:      ${ECR_URI}"
echo ""

# ---------------------------------------------------------------------------
# Cleanup mode
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "cleanup" ]]; then
    echo "Cleaning up..."
    aws ecs delete-cluster --cluster "${CLUSTER_NAME}" --region "${AWS_REGION}" 2>/dev/null || true
    aws ecr delete-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" --force 2>/dev/null || true
    aws logs delete-log-group --log-group-name "${LOG_GROUP}" --region "${AWS_REGION}" 2>/dev/null || true

    # Find and delete the IAM role
    ROLE_NAME="nono-fargate-execution-role"
    aws iam detach-role-policy --role-name "${ROLE_NAME}" \
        --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" 2>/dev/null || true
    aws iam delete-role --role-name "${ROLE_NAME}" 2>/dev/null || true

    # Delete security group
    SG_ID=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=nono-fargate-sg" "Name=vpc-id,Values=${VPC_ID}" \
        --query "SecurityGroups[0].GroupId" --output text --region "${AWS_REGION}" 2>/dev/null || echo "None")
    if [[ "${SG_ID}" != "None" && -n "${SG_ID}" ]]; then
        aws ec2 delete-security-group --group-id "${SG_ID}" --region "${AWS_REGION}" 2>/dev/null || true
    fi

    echo "Cleanup complete."
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 1: Create ECR repository
# ---------------------------------------------------------------------------
echo "[1/7] Creating ECR repository..."
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" --output text >/dev/null
echo "  Done."

# ---------------------------------------------------------------------------
# Step 2: Build and push container image
# ---------------------------------------------------------------------------
echo "[2/7] Building container image..."
aws ecr get-login-password --region "${AWS_REGION}" \
    | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

docker build -t "${ECR_REPO}:latest" -f "${NONO_ROOT}/examples/ecs-fargate/Dockerfile" "${NONO_ROOT}"
docker tag "${ECR_REPO}:latest" "${ECR_URI}:latest"

echo "  Pushing to ECR..."
docker push "${ECR_URI}:latest"
echo "  Done."

# ---------------------------------------------------------------------------
# Step 3: Create CloudWatch log group
# ---------------------------------------------------------------------------
echo "[3/7] Creating CloudWatch log group..."
aws logs describe-log-groups --log-group-name-prefix "${LOG_GROUP}" --region "${AWS_REGION}" \
    --query "logGroups[?logGroupName=='${LOG_GROUP}']" --output text | grep -q . \
    || aws logs create-log-group --log-group-name "${LOG_GROUP}" --region "${AWS_REGION}"
echo "  Done."

# ---------------------------------------------------------------------------
# Step 4: Create IAM execution role
# ---------------------------------------------------------------------------
echo "[4/7] Creating IAM execution role..."
ROLE_NAME="nono-fargate-execution-role"
ROLE_ARN=$(aws iam get-role --role-name "${ROLE_NAME}" --query "Role.Arn" --output text 2>/dev/null || echo "")

if [[ -z "${ROLE_ARN}" ]]; then
    TRUST_POLICY='{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'
    ROLE_ARN=$(aws iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document "${TRUST_POLICY}" \
        --query "Role.Arn" --output text)

    aws iam attach-role-policy \
        --role-name "${ROLE_NAME}" \
        --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"

    # IAM is eventually consistent - wait briefly
    sleep 10
fi
echo "  Role: ${ROLE_ARN}"

# ---------------------------------------------------------------------------
# Step 5: Create security group (egress-only, no inbound)
# ---------------------------------------------------------------------------
echo "[5/7] Creating security group..."
SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=nono-fargate-sg" "Name=vpc-id,Values=${VPC_ID}" \
    --query "SecurityGroups[0].GroupId" --output text --region "${AWS_REGION}" 2>/dev/null || echo "None")

if [[ "${SG_ID}" == "None" || -z "${SG_ID}" ]]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name "nono-fargate-sg" \
        --description "nono Fargate PoC - egress only" \
        --vpc-id "${VPC_ID}" \
        --region "${AWS_REGION}" \
        --query "GroupId" --output text)
fi
echo "  SG: ${SG_ID}"

# ---------------------------------------------------------------------------
# Step 6: Create ECS cluster + register task definition
# ---------------------------------------------------------------------------
echo "[6/7] Creating ECS cluster and task definition..."

aws ecs describe-clusters --clusters "${CLUSTER_NAME}" --region "${AWS_REGION}" \
    --query "clusters[?status=='ACTIVE']" --output text | grep -q . \
    || aws ecs create-cluster --cluster-name "${CLUSTER_NAME}" --region "${AWS_REGION}" --output text >/dev/null

# Generate task definition with real values substituted
TASK_DEF=$(cat "${NONO_ROOT}/examples/ecs-fargate/task-definition.json" \
    | sed "s|\${AWS_ACCOUNT_ID}|${AWS_ACCOUNT_ID}|g" \
    | sed "s|\${AWS_REGION}|${AWS_REGION}|g" \
    | sed "s|\${EXECUTION_ROLE_ARN}|${ROLE_ARN}|g")

echo "${TASK_DEF}" > /tmp/nono-task-def.json
aws ecs register-task-definition --cli-input-json file:///tmp/nono-task-def.json --region "${AWS_REGION}" --output text >/dev/null
rm /tmp/nono-task-def.json
echo "  Done."

# ---------------------------------------------------------------------------
# Step 7: Run the task
# ---------------------------------------------------------------------------
echo "[7/7] Running Fargate task..."
TASK_ARN=$(aws ecs run-task \
    --cluster "${CLUSTER_NAME}" \
    --task-definition "${TASK_FAMILY}" \
    --launch-type FARGATE \
    --platform-version "1.4.0" \
    --network-configuration "awsvpcConfiguration={subnets=[${SUBNET_ID}],securityGroups=[${SG_ID}],assignPublicIp=ENABLED}" \
    --region "${AWS_REGION}" \
    --query "tasks[0].taskArn" --output text)

echo ""
echo "============================================"
echo " Task launched: ${TASK_ARN}"
echo "============================================"
echo ""
echo "View logs:"
echo "  aws logs tail ${LOG_GROUP} --follow --region ${AWS_REGION}"
echo ""
echo "Check task status:"
echo "  aws ecs describe-tasks --cluster ${CLUSTER_NAME} --tasks ${TASK_ARN} --region ${AWS_REGION} --query 'tasks[0].lastStatus'"
echo ""
echo "Cleanup when done:"
echo "  ./deploy.sh cleanup"
