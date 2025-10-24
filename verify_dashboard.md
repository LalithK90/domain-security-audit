# Dashboard Verification Guide

## ✅ What the Dashboard Can Display

The `dashboard.html` is designed to display **ALL** sheets from your security reports:

### Supported Sheet Types:

1. **Security Results** (Subdomain view)
   - Shows all subdomains with scores, types, risk levels
   - Displays: Score, Type, Risk Level, Pass/Fail for each parameter
   - Filters: Type, Risk, Score range, Search

2. **Parameter Coverage Summary** (Coverage view)
   - Shows pass rates for each security control
   - Displays: Control_ID, Pass_Rate_%, Checked, Priority
   - Filters: Score range, Search by Control ID

3. **Standards Scores** (Compliance view)
   - Shows scores for compliance frameworks
   - Displays: Standard name, Score_%, Controls_Mapped
   - Filters: Score range, Search by standard name

4. **All Parameters** (Raw data view)
   - Shows detailed parameter-by-parameter results
   - All columns visible in table format

## 📊 Expected Sheets in ac.lk_security_report.xlsx

Based on the scanner code, your Excel file should contain:

1. `Security Results` - Main subdomain scores
2. `All Parameters` - Detailed parameter checks
3. `Parameter Coverage Summary` - Pass/fail rates per control
4. `Standards Scores` - Compliance framework scores

## 🔍 How to Verify the Dashboard Works

### Step 1: Open dashboard.html in Browser

```bash
# Option 1: Double-click dashboard.html
# Option 2: Open with command
open dashboard.html  # macOS
xdg-open dashboard.html  # Linux
start dashboard.html  # Windows
```

### Step 2: Upload the Excel File

1. Click the upload zone or drag-and-drop `ac.lk_security_report.xlsx`
2. Select which sheet you want to view from the dialog
3. Dashboard will automatically:
   - Detect the sheet type
   - Show appropriate filters
   - Display relevant help text
   - Render data in tables and charts

### Step 3: Verify Each Sheet

**Test 1: Security Results Sheet**
- ✅ Should show: Type filter, Risk filter, Score range, Search
- ✅ Should display: Subdomain names, scores (0-100), risk badges
- ✅ Charts: Score distribution pie chart, Type comparison bar chart

**Test 2: Parameter Coverage Summary**
- ✅ Should show: Score range filter, Search by Control ID
- ✅ Should hide: Type and Risk filters (not applicable)
- ✅ Should display: Control IDs (TLS-1, AUTH-5, etc.), pass rates

**Test 3: Standards Scores**
- ✅ Should show: Score range filter, Search by standard
- ✅ Should hide: Type and Risk filters
- ✅ Should display: ISO 27034, NIST SP 800-53, PSD2, HIPAA, etc.

**Test 4: All Parameters**
- ✅ Should show: All columns from Excel
- ✅ Should display: Raw data in table format

## 🎯 What Data is Displayed

The dashboard reads **EVERY column and row** from the selected sheet:

### From Security Results:
- Subdomain name
- Type (webapp/api/static/other)
- Total_Score
- Risk_Level
- Scan_Success
- All parameter pass/fail columns

### From Parameter Coverage Summary:
- Control_ID
- Parameter_Name
- Category
- Pass_Count
- Fail_Count
- Total_Checked
- Pass_Rate_%
- Priority

### From Standards Scores:
- Standard name
- Score_%
- Controls_Mapped
- Pass_Count
- Fail_Count

## 🐛 Troubleshooting

**Problem: Upload button doesn't work**
- Solution: Already fixed! Pull latest code:
  ```bash
  git pull origin master
  ```

**Problem: Sheet appears empty**
- Check browser console (F12) for errors
- Verify Excel file isn't corrupted
- Try different browser (Chrome recommended)

**Problem: Charts not showing**
- Wait a few seconds for data to load
- Check if data has numeric scores
- Refresh the page and try again

**Problem: Filters not working**
- Filters adapt based on sheet type
- Some filters hidden for non-subdomain sheets
- This is expected behavior!

## ✨ Features Summary

✅ Client-side processing (no server needed)
✅ Works offline
✅ Reads ALL sheets from Excel
✅ Detects sheet type automatically
✅ Adapts UI based on data
✅ Export to PDF
✅ Export filtered data to Excel
✅ Interactive charts
✅ Searchable tables
✅ Filter by type, risk, score range

## 🚀 Deployment

To deploy to GitHub Pages:

```bash
# 1. Commit dashboard.html
git add dashboard.html
git commit -m "Add interactive dashboard"
git push origin master

# 2. Enable GitHub Pages
# Go to: Settings → Pages → Source → Select 'master' branch

# 3. Access at:
# https://<username>.github.io/<repo-name>/dashboard.html
```

Users can then:
1. Visit the GitHub Pages URL
2. Upload their local Excel file
3. View interactive reports

---

**Summary:** The dashboard.html can display **ALL data** from ac.lk_security_report.xlsx. It automatically detects which sheet you're viewing and adapts the interface accordingly. Everything works client-side - no server required! 🎉
