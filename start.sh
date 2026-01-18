#!/usr/bin/env bash

# ============================================================================
# Security Scanner Orchestrator v3.0 - Queue-Based Sequential Processing
# ============================================================================
# Features:
# - Interactive domain input with JSON queue storage
# - Sequential domain processing (one at a time)
# - Excel report generated per domain completion
# - Low memory usage (no batch processing)
# - OS detection (macOS, Linux, Windows)
# - Timestamped report storage
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging
log() { printf "%b\n" "$*"; }
section() { log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; log "$*"; log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
info() { log "${GREEN}✓${NC} $*"; }
warn() { log "${YELLOW}⚠${NC} $*"; }
err() { log "${RED}✗${NC} $*"; exit 1; }

# ============================================================================
# 1. OS DETECTION
# ============================================================================

detect_os() {
    case "$(uname -s)" in
        Darwin*)  echo "macos" ;;
        Linux*)   echo "linux" ;;
        MINGW*|MSYS*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

OS=$(detect_os)

section "🖥️  System Detection"
info "OS detected: $(echo $OS | tr '[:lower:]' '[:upper:]')"

# ============================================================================
# 2. CHECK PREREQUISITES
# ============================================================================

check_prerequisites() {
    section "📋 Checking Prerequisites"
    
    if ! command -v python3 &>/dev/null; then
        err "Python 3 not found. Please install Python 3.8+"
    fi
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    info "Python $PYTHON_VERSION found"
}

# ============================================================================
# 3. ENVIRONMENT SETUP
# ============================================================================

setup_environment() {
    section "🔧 Setting Up Python Environment"
    
    if ! command -v conda &>/dev/null; then
        warn "Conda not found - attempting to initialize..."
        return 0
    fi
    
    ENV_NAME="security_audit_env"
    
    # Initialize conda if needed
    if ! type conda &>/dev/null; then
        eval "$(conda shell.bash hook)" 2>/dev/null || true
    fi
    
    # Create/activate environment
    if conda env list | grep -q "$ENV_NAME"; then
        info "Conda environment '$ENV_NAME' exists"
    else
        info "Creating conda environment '$ENV_NAME'..."
        conda create -n "$ENV_NAME" python=3.11 -y >/dev/null 2>&1
        info "Conda environment created"
    fi
    
    info "Installing/updating dependencies..."
    eval "$(conda shell.bash hook)" && conda activate "$ENV_NAME" && \
        pip install -q -r "$SCRIPT_DIR/requirements.txt" && \
        info "Dependencies ready"
}

# ============================================================================
# 4. SETUP OUTPUT DIRECTORY
# ============================================================================

setup_output_dir() {
    section "📁 Setting Up Output Directory"
    
    RUN_DATE=$(date +%Y-%m-%d)
    RUN_TIME=$(date +%H-%M-%S)
    RUN_TIMESTAMP=$(date +%Y-%m-%d\ %H:%M:%S)
    
    REPORT_DIR="$SCRIPT_DIR/reports/scans/${RUN_DATE}/${RUN_DATE}_${RUN_TIME}"
    mkdir -p "$REPORT_DIR"
    
    info "Reports will be saved to: $REPORT_DIR"
}

# ============================================================================
# 5. DOMAIN INPUT - Interactive or from arguments
# ============================================================================

get_domains() {
    section "🔐 Domain Input"
    
    # If domains provided as arguments, use them
    if [ $# -gt 0 ]; then
        info "Using domains from command line: ${*}"
        python "$SCRIPT_DIR/queue/domain_queue_manager.py" init "${@}"
        return $?
    fi
    
    # Otherwise, interactive input
    log "\n${CYAN}Interactive Domain Input Mode${NC}"
    log "Enter domain(s) to scan (one per line):"
    log "  Examples: google.com, github.com, example.org"
    log "  Type 'done' when finished\n"
    
    python "$SCRIPT_DIR/queue/domain_queue_manager.py"
}

# ============================================================================
# 6. PROCESS DOMAIN QUEUE
# ============================================================================

process_queue() {
    section "🔄 Processing Domain Queue"
    
    while true; do
        # Get next domain
        NEXT_DOMAIN=$(python "$SCRIPT_DIR/queue/domain_queue_manager.py" next)
        
        if [ -z "$NEXT_DOMAIN" ]; then
            info "All domains processed!"
            break
        fi
        
        log ""
        info "Processing domain: $NEXT_DOMAIN"
        info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # Activate conda environment
        if command -v conda &>/dev/null; then
            eval "$(conda shell.bash hook)" && conda activate security_audit_env 2>/dev/null || true
        fi
        
        # Run scanner for this domain (M1 Mac optimized: 500 workers, no rate limit)
        if python "$SCRIPT_DIR/src/security_scanner.py" \
            --domain "$NEXT_DOMAIN" \
            --output-dir "$REPORT_DIR" \
            --workers 500 \
            --rate-limit 0; then
            
            # Mark as completed
            python "$SCRIPT_DIR/queue/domain_queue_manager.py" complete "$NEXT_DOMAIN"
            info "✅ Completed: $NEXT_DOMAIN"
            
            # Update master tracker queue status
            python "$SCRIPT_DIR/queue/master_tracker.py" update-queue
            
            # Show queue status
            STATUS=$(python "$SCRIPT_DIR/queue/domain_queue_manager.py" status)
            info "Queue status: $(echo "$STATUS" | grep 'Remaining' | awk -F': ' '{print $2}')"
        else
            # Mark as failed
            python "$SCRIPT_DIR/queue/domain_queue_manager.py" fail "$NEXT_DOMAIN" "scan_failed"
            warn "❌ Failed: $NEXT_DOMAIN - continuing with next domain"
        fi
        
        log ""
    done
}

# ============================================================================
# 7. SHOW FINAL REPORT
# ============================================================================

show_report() {
    section "📊 Scan Summary"
    
    info "Reports saved to: $REPORT_DIR"
    info ""
    info "📋 Files generated:"
    
    if [ -d "$REPORT_DIR" ]; then
        find "$REPORT_DIR" -maxdepth 1 -name "*.xlsx" -type f | while read f; do
            basename "$f" | sed 's/^/   /'
        done
    fi
    
    info ""
    info "View reports at:"
    info "   $REPORT_DIR"
    
    # Show master tracker summary
    info ""
    python "$SCRIPT_DIR/queue/master_tracker.py" summary
}

# ============================================================================
# 8. MAIN EXECUTION
# ============================================================================

main() {
    check_prerequisites
    setup_environment
    setup_output_dir
    
    # Initialize master tracker before processing
    python "$SCRIPT_DIR/queue/master_tracker.py" init
    
    get_domains "${@}"
    process_queue
    show_report
    
    section "✅ SECURITY AUDIT COMPLETE"
    info "All domains have been scanned and reports generated"
}

main "${@}"
