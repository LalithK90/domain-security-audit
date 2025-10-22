#!/bin/bash

# Quick Start Script for Comprehensive Security Scanning
# This script helps you generate a complete security report with all 106 parameters

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🔒 Comprehensive Security Scanner - Quick Start"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Colors for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "What would you like to do?"
echo ""
echo "  1️⃣  Quick Test (3 subdomains, ~30 seconds)"
echo "  2️⃣  Full Scan of ac.lk domain (960+ subdomains, 2-3 hours)"
echo "  3️⃣  Scan from custom file"
echo "  4️⃣  Process existing report (add comprehensive sheets)"
echo "  5️⃣  View documentation"
echo "  6️⃣  Exit"
echo ""
read -p "Enter choice [1-6]: " choice

case $choice in
    1)
        echo ""
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo "${GREEN}Running Quick Test...${NC}"
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "This will test 3 known ac.lk subdomains to verify everything works."
        echo "Time: ~30 seconds"
        echo "Output: test_comprehensive.xlsx"
        echo ""
        read -p "Continue? [Y/n]: " confirm
        if [[ $confirm != "n" && $confirm != "N" ]]; then
            python test_scanner.py
            if [ $? -eq 0 ]; then
                echo ""
                echo "${GREEN}✅ Test completed successfully!${NC}"
                echo ""
                echo "Next steps:"
                echo "  • Open test_comprehensive.xlsx"
                echo "  • Check 'All 106 Parameters' sheet"
                echo "  • Verify Pass/Fail data is present"
                echo ""
                read -p "Open test_comprehensive.xlsx now? [Y/n]: " open_test
                if [[ $open_test != "n" && $open_test != "N" ]]; then
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        open test_comprehensive.xlsx
                    else
                        xdg-open test_comprehensive.xlsx 2>/dev/null || echo "Please open test_comprehensive.xlsx manually"
                    fi
                fi
            fi
        fi
        ;;
        
    2)
        echo ""
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo "${YELLOW}⚠️  Full Scan Warning${NC}"
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "This will scan ALL ac.lk subdomains with comprehensive parameter collection."
        echo ""
        echo "  • Estimated time: 2-3 hours"
        echo "  • Expected subdomains: 900-1000+"
        echo "  • Data points collected: ~100,000+"
        echo "  • Output: ac.lk_security_report.xlsx"
        echo ""
        echo "Tips:"
        echo "  • Run overnight or during lunch"
        echo "  • Keep terminal window open"
        echo "  • Check progress periodically"
        echo ""
        read -p "Continue with full scan? [y/N]: " confirm
        if [[ $confirm == "y" || $confirm == "Y" ]]; then
            # Backup existing report if it exists
            if [ -f "ac.lk_security_report.xlsx" ]; then
                echo ""
                echo "Backing up existing report..."
                cp ac.lk_security_report.xlsx "ac.lk_security_report_$(date +%Y%m%d_%H%M%S).xlsx"
                echo "${GREEN}✓ Backup created${NC}"
            fi
            
            echo ""
            echo "${GREEN}Starting full scan...${NC}"
            echo "${YELLOW}This will take 2-3 hours. Press Ctrl+C to cancel.${NC}"
            echo ""
            python security_scanner.py ac.lk
            
            if [ $? -eq 0 ]; then
                echo ""
                echo "${GREEN}════════════════════════════════════════════════════════════════════════════════${NC}"
                echo "${GREEN}✅ Full Scan Completed Successfully!${NC}"
                echo "${GREEN}════════════════════════════════════════════════════════════════════════════════${NC}"
                echo ""
                echo "Report saved to: ac.lk_security_report.xlsx"
                echo ""
                echo "The report includes:"
                echo "  ✓ All 106 Parameters (complete Pass/Fail matrix)"
                echo "  ✓ Data Collection Evidence (what was tested)"
                echo "  ✓ Parameter Coverage Summary (failure rates)"
                echo "  ✓ Type-specific rankings (webapp/api/static/other)"
                echo ""
                read -p "Open report now? [Y/n]: " open_report
                if [[ $open_report != "n" && $open_report != "N" ]]; then
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        open ac.lk_security_report.xlsx
                    else
                        xdg-open ac.lk_security_report.xlsx 2>/dev/null || echo "Please open ac.lk_security_report.xlsx manually"
                    fi
                fi
            else
                echo ""
                echo "${RED}❌ Scan failed or was interrupted${NC}"
                echo "Check the error messages above for details."
            fi
        fi
        ;;
        
    3)
        echo ""
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo "${GREEN}Scan from Custom File${NC}"
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Enter the path to your subdomain list file (.txt or .xlsx):"
        read -p "File path: " input_file
        
        if [ ! -f "$input_file" ]; then
            echo "${RED}❌ File not found: $input_file${NC}"
            exit 1
        fi
        
        # Count lines/subdomains
        if [[ "$input_file" == *.txt ]]; then
            subdomain_count=$(wc -l < "$input_file" | tr -d ' ')
            echo ""
            echo "Found $subdomain_count subdomains in file"
        fi
        
        echo ""
        read -p "Output filename (default: security_report.xlsx): " output_file
        output_file=${output_file:-security_report.xlsx}
        
        echo ""
        echo "Starting scan..."
        echo "  Input: $input_file"
        echo "  Output: $output_file"
        echo ""
        
        python security_scanner.py --file "$input_file" --output "$output_file"
        
        if [ $? -eq 0 ]; then
            echo ""
            echo "${GREEN}✅ Scan completed successfully!${NC}"
            echo "Report saved to: $output_file"
        fi
        ;;
        
    4)
        echo ""
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo "${GREEN}Process Existing Report${NC}"
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "This will add comprehensive sheets to an existing report."
        echo ""
        echo "⚠️  Note: This only works if the original report has individual parameter columns."
        echo "   If your report only has summary scores, you'll need to re-run the full scan."
        echo ""
        read -p "Enter report filename (e.g., ac.lk_security_report.xlsx): " report_file
        
        if [ ! -f "$report_file" ]; then
            echo "${RED}❌ File not found: $report_file${NC}"
            exit 1
        fi
        
        echo ""
        echo "Processing report..."
        python add_comprehensive_sheets.py "$report_file"
        
        if [ $? -eq 0 ]; then
            output="${report_file%.xlsx}_COMPREHENSIVE.xlsx"
            echo ""
            echo "${GREEN}✅ Processing completed!${NC}"
            echo "Enhanced report saved to: $output"
            echo ""
            read -p "Open enhanced report? [Y/n]: " open_report
            if [[ $open_report != "n" && $open_report != "N" ]]; then
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    open "$output"
                else
                    xdg-open "$output" 2>/dev/null || echo "Please open $output manually"
                fi
            fi
        fi
        ;;
        
    5)
        echo ""
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo "${GREEN}Documentation${NC}"
        echo "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Available documentation files:"
        echo ""
        echo "  1. COMPREHENSIVE_REPORT_GUIDE.md - Complete usage guide"
        echo "  2. SCANNER_UPDATE_SUMMARY.md - What was changed and why"
        echo "  3. VISUAL_COMPARISON.md - Old vs new report comparison"
        echo "  4. SCORING_GUIDE.md - How scoring works"
        echo ""
        read -p "Which file to view? [1-4 or press Enter to skip]: " doc_choice
        
        case $doc_choice in
            1) cat COMPREHENSIVE_REPORT_GUIDE.md | more ;;
            2) cat SCANNER_UPDATE_SUMMARY.md | more ;;
            3) cat VISUAL_COMPARISON.md | more ;;
            4) cat SCORING_GUIDE.md | more ;;
            *) echo "Skipping documentation view" ;;
        esac
        ;;
        
    6)
        echo ""
        echo "Goodbye! 👋"
        echo ""
        exit 0
        ;;
        
    *)
        echo ""
        echo "${RED}Invalid choice. Please run again and select 1-6.${NC}"
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "Done! Run './quickstart.sh' again for more options."
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
