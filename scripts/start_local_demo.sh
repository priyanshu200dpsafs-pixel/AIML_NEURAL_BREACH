#!/usr/bin/env bash
# ==============================================================================
# Team Neural Breach — Interactive SOC Application Launcher
# Starts the unified Python backend service and serves the production
# React SOC Analyst Dashboard at http://127.0.0.1:8000/ui
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "   TEAM NEURAL BREACH — CYBER DEFENSE PLATFORM & SOC DASHBOARD"
echo "   Governance: OBSERVE-ONLY (Action Enforced: NONE_OBSERVE_ONLY)"
echo "======================================================================"

# 1. Environment and dependency sanity check
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required but not found in PATH." >&2
    exit 1
fi

echo "[*] Verifying frozen ML artifacts in models/role3_retrain_v2/..."
if [ ! -f "models/role3_retrain_v2/supervised/supervised_lightgbm_primary.joblib" ]; then
    echo "[-] Error: Frozen model artifact missing: supervised_lightgbm_primary.joblib" >&2
    exit 1
fi
echo "[+] All frozen models present and verified."

# 2. Check or build frontend static distribution
if [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Frontend distribution not found. Building production bundle via Vite..."
    if command -v npm &>/dev/null; then
        cd frontend
        npm run build
        cd "$PROJECT_ROOT"
    else
        echo "[-] Error: npm is required to build frontend but was not found." >&2
        exit 1
    fi
fi
echo "[+] Production React SOC Dashboard ready at frontend/dist/"

# 3. Launch service
PORT="${NEURAL_BREACH_PORT:-8000}"
HOST="${NEURAL_BREACH_HOST:-127.0.0.1}"

echo ""
echo "----------------------------------------------------------------------"
echo "  SOC Command Console URL : http://${HOST}:${PORT}/ui"
echo "  Backend API Spec Docs   : http://${HOST}:${PORT}/docs"
echo "  Health Probe            : http://${HOST}:${PORT}/api/v1/health"
echo "  WebSocket Alert Stream  : ws://${HOST}:${PORT}/ws/alerts"
echo "----------------------------------------------------------------------"
echo "[*] Evaluation Quick Access:"
echo "    1. Open http://${HOST}:${PORT}/ui in your web browser."
echo "    2. Click 'Launch SOC Analyst Console' for 1-click observer access."
echo "    3. Navigate to 'Demo Scenarios' to execute live ML inference & SHAP."
echo "----------------------------------------------------------------------"
echo ""

exec python3 -m src.backend.run_server --host "$HOST" --port "$PORT"

