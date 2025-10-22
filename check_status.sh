#!/usr/bin/env bash

# Check Status of Security Scans
# Use this to monitor running scans after disconnecting SSH

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "════════════════════════════════════════════════════════════════════════════════"
echo -e "${BLUE}🔍 Security Scanner Status Check${NC}"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check for PID files
AC_PID_FILE=".ac_lk_scan.pid"
GOV_PID_FILE=".gov_lk_scan.pid"

# Function to check if process is running
check_process() {
    local pid_file=$1
    local domain=$2
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $domain scan is running${NC} (PID: $pid)"
            
            # Find and show the log file
            local log_file=$(ls -t ${domain}_scan_*.log 2>/dev/null | head -1)
            if [ -f "$log_file" ]; then
                echo "   Log: $log_file"
                local log_size=$(wc -l < "$log_file")
                echo "   Lines logged: $log_size"
            fi
            return 0
        else
            echo -e "${YELLOW}⚠️  $domain scan process not found${NC} (PID $pid no longer running)"
            return 1
        fi
    else
        echo -e "${BLUE}ℹ️  $domain scan not currently running${NC}"
        return 2
    fi
}

# Check ac.lk scan
check_process "$AC_PID_FILE" "ac.lk"
AC_STATUS=$?

echo ""

# Check gov.lk scan
check_process "$GOV_PID_FILE" "gov.lk"
GOV_STATUS=$?

echo ""
echo "────────────────────────────────────────────────────────────────────────────────"

# Check for completed reports
echo ""
echo -e "${BLUE}📊 Report Files:${NC}"
if [ -f "ac.lk_security_report.xlsx" ]; then
    ac_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "ac.lk_security_report.xlsx" 2>/dev/null || stat -c "%y" "ac.lk_security_report.xlsx" 2>/dev/null | cut -d'.' -f1)
    ac_size=$(du -h "ac.lk_security_report.xlsx" | cut -f1)
    echo -e "   ${GREEN}✓${NC} ac.lk_security_report.xlsx ($ac_size, modified: $ac_time)"
else
    echo -e "   ${YELLOW}✗${NC} ac.lk_security_report.xlsx (not found)"
fi

if [ -f "gov.lk_security_report.xlsx" ]; then
    gov_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "gov.lk_security_report.xlsx" 2>/dev/null || stat -c "%y" "gov.lk_security_report.xlsx" 2>/dev/null | cut -d'.' -f1)
    gov_size=$(du -h "gov.lk_security_report.xlsx" | cut -f1)
    echo -e "   ${GREEN}✓${NC} gov.lk_security_report.xlsx ($gov_size, modified: $gov_time)"
else
    echo -e "   ${YELLOW}✗${NC} gov.lk_security_report.xlsx (not found)"
fi

echo ""
echo "────────────────────────────────────────────────────────────────────────────────"

# Show recent log files
echo ""
echo -e "${BLUE}📝 Recent Log Files:${NC}"
recent_logs=$(ls -t *_scan_*.log start_run_*.log 2>/dev/null | head -5)
if [ -n "$recent_logs" ]; then
    echo "$recent_logs" | while read log; do
        log_size=$(wc -l < "$log")
        echo "   • $log ($log_size lines)"
    done
else
    echo "   No recent log files found"
fi

echo ""
echo "────────────────────────────────────────────────────────────────────────────────"

# Provide helpful commands
echo ""
echo -e "${BLUE}💡 Useful Commands:${NC}"
echo ""

if [ $AC_STATUS -eq 0 ] || [ $GOV_STATUS -eq 0 ]; then
    echo "Monitor scan logs in real-time:"
    if [ $AC_STATUS -eq 0 ]; then
        ac_log=$(ls -t ac.lk_scan_*.log 2>/dev/null | head -1)
        echo "  tail -f $ac_log"
    fi
    if [ $GOV_STATUS -eq 0 ]; then
        gov_log=$(ls -t gov_lk_scan_*.log 2>/dev/null | head -1)
        echo "  tail -f $gov_log"
    fi
    echo ""
fi

echo "View main execution log:"
main_log=$(ls -t start_run_*.log 2>/dev/null | head -1)
if [ -n "$main_log" ]; then
    echo "  tail -f $main_log"
else
    echo "  (No main log found)"
fi

echo ""
echo "Check system resources:"
echo "  top -u \$(whoami)"
echo ""

echo "════════════════════════════════════════════════════════════════════════════════"
