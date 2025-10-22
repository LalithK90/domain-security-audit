#!/usr/bin/env bash

# Automated Security Scanner Runner
# This script: 1) Pulls latest code, 2) Runs scans, 3) Pushes results to GitHub
# Can run safely even after SSH disconnect

set -e  # Exit on any error

# Redirect all output to log file if not already redirected
MAIN_LOG="start_run_$(date '+%Y%m%d_%H%M%S').log"
if [ -t 1 ]; then
    # Running interactively - redirect to log file
    exec > >(tee -a "$MAIN_LOG") 2>&1
    echo "📝 Logging to: $MAIN_LOG"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "════════════════════════════════════════════════════════════════════════════════"
echo -e "${BLUE}🔒 Automated Security Scanner - Start${NC}"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${YELLOW}📂 Working directory: $SCRIPT_DIR${NC}"
echo ""

# ============================================================================
# STEP 1: Check for GitHub updates and pull
# ============================================================================
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 1: Checking for GitHub updates...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Fetch latest from origin
echo "Fetching latest changes from GitHub..."
git fetch origin

# Check if we're behind
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo -e "${YELLOW}⚠️  Updates found! Pulling latest code...${NC}"
    git pull origin master
    echo -e "${GREEN}✅ Code updated successfully${NC}"
else
    echo -e "${GREEN}✅ Already up to date${NC}"
fi
echo ""

# ============================================================================
# STEP 2: Check/Create/Activate Python virtual environment
# ============================================================================
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 2: Setting up Python virtual environment...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

VENV_DIR="venv"

# Check if venv directory exists
if [ -d "$VENV_DIR" ]; then
    echo -e "${GREEN}✅ Virtual environment found: $VENV_DIR${NC}"
else
    echo -e "${YELLOW}⚠️  Virtual environment not found. Creating new venv...${NC}"
    
    # Create virtual environment
    python3 -m venv "$VENV_DIR"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Virtual environment created successfully${NC}"
        
        # Activate and install dependencies
        . "$VENV_DIR/bin/activate"
        
        if [ -f "requirements.txt" ]; then
            echo "Installing dependencies from requirements.txt..."
            pip install --upgrade pip
            pip install -r requirements.txt
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Dependencies installed${NC}"
            else
                echo -e "${RED}❌ Failed to install dependencies${NC}"
                exit 1
            fi
        fi
    else
        echo -e "${RED}❌ Failed to create virtual environment${NC}"
        exit 1
    fi
fi

# Activate the virtual environment
echo "Activating virtual environment..."
. "$VENV_DIR/bin/activate"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Environment activated: $(which python)${NC}"
    python --version
else
    echo -e "${RED}❌ Failed to activate virtual environment${NC}"
    exit 1
fi
echo ""

# ============================================================================
# STEP 3: Run security scans (in parallel)
# ============================================================================
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 3: Running security scans in parallel...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Get current timestamp for filenames and commit message
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
FILE_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

echo -e "${YELLOW}🔍 Starting both domain scans simultaneously...${NC}"
echo ""
echo "  • ac.lk  → ac.lk_security_report.xlsx"
echo "  • gov.lk → gov.lk_security_report.xlsx"
echo ""
echo "Started at: $(date '+%H:%M:%S')"
echo ""

# Create log files for each scan
AC_LOG="ac_lk_scan_${FILE_TIMESTAMP}.log"
GOV_LOG="gov_lk_scan_${FILE_TIMESTAMP}.log"

# Run both scans in background
echo -e "${BLUE}[ac.lk]${NC}  Scan running in background... (log: $AC_LOG)"
nohup python security_scanner.py ac.lk --output ac.lk_security_report.xlsx > "$AC_LOG" 2>&1 &
AC_PID=$!

echo -e "${BLUE}[gov.lk]${NC} Scan running in background... (log: $GOV_LOG)"
nohup python security_scanner.py gov.lk --output gov.lk_security_report.xlsx > "$GOV_LOG" 2>&1 &
GOV_PID=$!

# Save PIDs to file for later monitoring
echo "$AC_PID" > .ac_lk_scan.pid
echo "$GOV_PID" > .gov_lk_scan.pid

echo ""
echo "Background processes started:"
echo "  • ac.lk  (PID: $AC_PID)"
echo "  • gov.lk (PID: $GOV_PID)"
echo ""
echo -e "${YELLOW}⏳ Waiting for both scans to complete...${NC}"
echo "   (This may take 2-3 hours depending on subdomain count)"
echo ""

# Wait for both processes and track their exit codes
wait $AC_PID
AC_EXIT=$?

wait $GOV_PID
GOV_EXIT=$?

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "Scan Results:"
echo "════════════════════════════════════════════════════════════════════════════════"

# Check ac.lk result
if [ $AC_EXIT -eq 0 ]; then
    echo -e "${GREEN}✅ ac.lk scan completed successfully${NC}"
else
    echo -e "${RED}❌ ac.lk scan failed (exit code: $AC_EXIT)${NC}"
    echo "   Check log: $AC_LOG"
fi

# Check gov.lk result
if [ $GOV_EXIT -eq 0 ]; then
    echo -e "${GREEN}✅ gov.lk scan completed successfully${NC}"
else
    echo -e "${RED}❌ gov.lk scan failed (exit code: $GOV_EXIT)${NC}"
    echo "   Check log: $GOV_LOG"
fi

echo ""
echo "Finished at: $(date '+%H:%M:%S')"
echo ""

# Exit with error if any scan failed
if [ $AC_EXIT -ne 0 ] || [ $GOV_EXIT -ne 0 ]; then
    echo -e "${RED}❌ One or more scans failed. Check the logs above.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All scans completed successfully!${NC}"
echo ""

# Clean up PID files
rm -f .ac_lk_scan.pid .gov_lk_scan.pid

# Clean up log files if scans were successful
rm -f "$AC_LOG" "$GOV_LOG"
echo -e "${BLUE}ℹ️  Scan logs deleted (both scans successful)${NC}"
echo ""

# ============================================================================
# STEP 4: Push results to GitHub
# ============================================================================
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Step 4: Pushing results to GitHub...${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if there are any changes to commit
if [ -n "$(git status --porcelain)" ]; then
    echo "Changes detected. Staging files..."
    
    # Add the report files
    git add ac.lk_security_report.xlsx
    git add gov.lk_security_report.xlsx
    
    # Add any other changed files (code updates, etc.)
    git add -A
    
    echo "Files staged. Creating commit..."
    
    # Create commit with timestamp
    COMMIT_MESSAGE="$TIMESTAMP successfully run"
    git commit -m "$COMMIT_MESSAGE"
    
    echo "Pushing to GitHub..."
    git push origin master
    
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✅ Results pushed to GitHub successfully${NC}"
        echo -e "${GREEN}   Commit: $COMMIT_MESSAGE${NC}"
    else
        echo ""
        echo -e "${RED}❌ Failed to push to GitHub${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}ℹ️  No changes to commit${NC}"
fi
echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Automation Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "📊 Reports generated:"
echo "   • ac.lk_security_report.xlsx"
echo "   • gov.lk_security_report.xlsx"
echo ""
echo "📦 Results pushed to GitHub"
echo "   Repository: $(git config --get remote.origin.url)"
echo ""
echo "⏰ Completed at: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
