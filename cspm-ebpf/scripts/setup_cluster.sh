#!/bin/bash
set -e

# Add local bin to path
export PATH="$PWD/bin:$PATH"

CLUSTER_NAME="sentinel-cluster"

echo "====================================="
echo "Sentinel-Core: Infrastructure Setup"
echo "====================================="

# 1. Check prerequisites
for cmd in docker kind helm kubectl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed."
        exit 1
    fi
done

# 2. Create Kind cluster if it doesn't exist
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster '${CLUSTER_NAME}' already exists."
else
    echo "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --name "${CLUSTER_NAME}"
fi

# 3. Add Cilium Helm repo
echo "Adding Cilium Helm repository..."
helm repo add cilium https://helm.cilium.io
helm repo update

# 4. Install Tetragon
echo "Installing Tetragon into kube-system namespace..."
# We use hostNetwork=true and mount proc/sys for eBPF to monitor the whole host/nodes natively
helm upgrade --install tetragon cilium/tetragon -n kube-system --wait

echo "Waiting for Tetragon pods to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=120s

echo "====================================="
echo "✅ Infrastructure Setup Complete"
echo "====================================="
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
