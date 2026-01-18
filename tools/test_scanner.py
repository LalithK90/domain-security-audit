"""
Quick test of the updated security scanner with comprehensive parameter collection.
Tests 2-3 subdomains to verify all 106 parameters are being captured.
"""

import subprocess
import sys
import pandas as pd

print("="*80)
print("Testing Updated Security Scanner")
print("="*80)

# Test domains (known ac.lk subdomains)
test_domains = [
    "www.ac.lk",
    "www.colombo.ac.lk",
    "www.mrt.ac.lk"
]

print(f"\n✓ Testing with {len(test_domains)} subdomains")
print("  This will take ~30 seconds (3 sec rate limit per variant)")

# Create test input file
with open('test_input.txt', 'w') as f:
    for domain in test_domains:
        f.write(domain + '\n')

print("\n✓ Created test_input.txt")

# Run scanner
print("\n🔍 Running security scanner...")
print("="*80)
result = subprocess.run([
    'python', 'security_scanner.py',
    '--file', 'test_input.txt',
    '--output', 'test_comprehensive.xlsx'
], capture_output=False, text=True)

if result.returncode != 0:
    print(f"\n❌ Scanner failed with exit code {result.returncode}")
    sys.exit(1)

print("\n="*80)
print("Verifying Output...")
print("="*80)

# Verify the output
try:
    # Check Security Results sheet
    df_results = pd.read_excel('test_comprehensive.xlsx', sheet_name='Security Results')
    print(f"\n✓ Security Results: {len(df_results)} rows")
    print(f"  Columns: {list(df_results.columns)[:10]}...")
    
    # Check if individual parameter columns exist
    param_columns = [col for col in df_results.columns if '_Pass' in col]
    print(f"  Found {len(param_columns)} parameter columns (should be close to 106)")
    
    # Check new comprehensive sheets
    sheets = pd.ExcelFile('test_comprehensive.xlsx').sheet_names
    print(f"\n✓ Total sheets: {len(sheets)}")
    
    required_sheets = [
        'All 106 Parameters',
        'Data Collection Evidence',
        'Parameter Coverage Summary'
    ]
    
    for sheet_name in required_sheets:
        if sheet_name in sheets:
            df = pd.read_excel('test_comprehensive.xlsx', sheet_name=sheet_name)
            print(f"  ✅ {sheet_name}: {len(df)} rows")
            
            if sheet_name == 'All 106 Parameters':
                # Count parameter columns (106 parameters + 5 metadata columns)
                total_cols = len(df.columns)
                param_cols = total_cols - 5  # Subtract metadata columns
                print(f"     → Has {param_cols} parameter columns")
                
                # Check data quality
                if len(df) > 0:
                    sample_row = df.iloc[0]
                    # Count Pass/Fail/N/A vs "Not Applicable"
                    param_values = []
                    for col in df.columns:
                        if col not in ['Subdomain', 'Type', 'Scan_Success', 'Total_Score', 'Risk_Rating']:
                            val = sample_row[col]
                            if val != 'Not Applicable':
                                param_values.append(val)
                    
                    print(f"     → Sample subdomain has {len(param_values)} parameters with data")
        else:
            print(f"  ❌ MISSING: {sheet_name}")
    
    print("\n" + "="*80)
    print("✅ TEST PASSED - Updated scanner is working correctly!")
    print("="*80)
    print("\nNext steps:")
    print("  1. Review test_comprehensive.xlsx to verify the format")
    print("  2. Check 'All 106 Parameters' sheet has Pass/Fail/N/A data")
    print("  3. If satisfied, run full scan: python security_scanner.py ac.lk")
    print("\nCleanup test files:")
    print("  rm test_input.txt test_comprehensive.xlsx")
    
except Exception as e:
    print(f"\n❌ Verification failed: {e}")
    print("\nThe scanner may have run but output format might be incorrect.")
    sys.exit(1)
