#!/bin/sh

# Automated Security Scanner Runner
# Simple POSIX-compatible version

set -e

echo "======================================================================"
echo "Security Scanner - Starting"
echo "======================================================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ====================================================================
# STEP 1: Git Pull
# ====================================================================
echo "[Step 1/3] Checking for updates from GitHub..."
git fetch origin > /dev/null 2>&1

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "           Updates found. Pulling..."
    git pull origin master > /dev/null 2>&1
    echo "           Done."
else
    echo "           Already up to date."
fi
echo ""

# ====================================================================
# STEP 2: Python Environment
# ====================================================================
echo "[Step 2/3] Setting up Python environment..."

VENV_DIR="venv"

if [ -d "$VENV_DIR" ]; then
    echo "           Virtual environment found."
else
    echo "           Creating new virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    . "$VENV_DIR/bin/activate"
    
    if [ -f "requirements.txt" ]; then
        echo "           Installing dependencies..."
        pip install --upgrade pip > /dev/null 2>&1
        pip install -r requirements.txt > /dev/null 2>&1
    fi
    
    echo "           Environment created."
fi

# Activate environment
. "$VENV_DIR/bin/activate"
echo "           Environment activated."
echo ""

# ====================================================================
# STEP 3: Run Scans
# ====================================================================
echo "[Step 3/3] Starting security scans in background..."
echo ""

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
FILE_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Log files
AC_LOG="ac_lk_scan_${FILE_TIMESTAMP}.log"
GOV_LOG="gov_lk_scan_${FILE_TIMESTAMP}.log"
MAIN_LOG="start_run_${FILE_TIMESTAMP}.log"

echo "Starting scans for ac.lk and gov.lk..."
echo "Logs: $AC_LOG, $GOV_LOG"
echo ""

# Run scans in background
# nohup python security_scanner.py ac.lk --output ac.lk_security_report.xlsx > "$AC_LOG" 2>&1 &
# AC_PID=$!

nohup python security_scanner.py gov.lk --output gov.lk_security_report.xlsx > "$GOV_LOG" 2>&1 &
GOV_PID=$!

# Save PIDs
echo "$AC_PID" > .ac_lk_scan.pid
echo "$GOV_PID" > .gov_lk_scan.pid

echo "Scans running in background:"
echo "  - ac.lk  (PID: $AC_PID)"
echo "  - gov.lk (PID: $GOV_PID)"
echo ""
echo "======================================================================"
echo "Scans Started Successfully"
echo "======================================================================"
echo ""
echo "The scans will take 2-3 hours to complete."
echo "You can safely disconnect SSH now."
echo ""
echo "To check status later, run:"
echo "  bash check_status.sh"
echo ""
echo "To view logs:"
echo "  tail -f $AC_LOG"
echo "  tail -f $GOV_LOG"
echo ""

# Continue monitoring in background
(
    # Wait for both scans
    wait $AC_PID
    AC_EXIT=$?
    
    wait $GOV_PID
    GOV_EXIT=$?
    
    # Log results
    echo "" >> "$MAIN_LOG"
    echo "Scan completed at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$MAIN_LOG"
    echo "ac.lk exit code: $AC_EXIT" >> "$MAIN_LOG"
    echo "gov.lk exit code: $GOV_EXIT" >> "$MAIN_LOG"
    
    # If both successful, push to GitHub
    if [ $AC_EXIT -eq 0 ] && [ $GOV_EXIT -eq 0 ]; then
        cd "$SCRIPT_DIR"
        
        if [ -n "$(git status --porcelain)" ]; then
            git add ac.lk_security_report.xlsx gov.lk_security_report.xlsx
            git add -A
            git commit -m "$TIMESTAMP successfully run"
            git push origin master
            
            echo "Results pushed to GitHub at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$MAIN_LOG"
            
            # Clean up scan logs on success
            rm -f "$AC_LOG" "$GOV_LOG"
        fi
        
        # Clean up PID files
        rm -f .ac_lk_scan.pid .gov_lk_scan.pid
    else
        echo "One or more scans failed. Check logs." >> "$MAIN_LOG"
    fi
) >> "$MAIN_LOG" 2>&1 &

echo "Background monitoring started."
echo "Main log: $MAIN_LOG"
echo ""
echo "======================================================================"

