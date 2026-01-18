import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import re
import urllib.parse as urlparse

# Set page configuration
st.set_page_config(
    page_title="🔒 Network Security Report Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        color: #1E88E5;
        text-align: center;
        padding: 20px;
        background: linear-gradient(90deg, #E3F2FD 0%, #BBDEFB 100%);
        border-radius: 10px;
        margin-bottom: 30px;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #424242;
        padding: 10px;
        background-color: #F5F5F5;
        border-radius: 5px;
        margin: 10px 0;
    }
    .info-box {
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .safe-box {
        background-color: #C8E6C9;
        border-left: 5px solid #4CAF50;
    }
    .warning-box {
        background-color: #FFF9C4;
        border-left: 5px solid #FFC107;
    }
    .danger-box {
        background-color: #FFCDD2;
        border-left: 5px solid #F44336;
    }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        text-align: center;
    }
    /* Styling for clickable tables */
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 20px 0;
        font-size: 14px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    th {
        background-color: #1E88E5;
        color: white;
        padding: 12px;
        text-align: left;
        font-weight: bold;
        position: sticky;
        top: 0;
        z-index: 10;
    }
    td {
        padding: 10px 12px;
        border-bottom: 1px solid #ddd;
    }
    tr:hover {
        background-color: #f5f5f5;
    }
    tr:nth-child(even) {
        background-color: #f9f9f9;
    }
    /* Clickable URL styling */
    a {
        color: #1E88E5;
        text-decoration: none;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    a:hover {
        color: #0D47A1;
        text-decoration: underline;
        font-weight: bold;
    }
    a:visited {
        color: #7B1FA2;
    }
    /* Make table scrollable */
    .dataframe-container {
        max-height: 600px;
        overflow-y: auto;
        margin: 20px 0;
    }
    /* Button-like links used in table */
    a.btn-link {
        display: inline-block;
        background-color: #1E88E5;
        color: white !important;
        padding: 6px 10px;
        border-radius: 6px;
        text-decoration: none !important;
        font-size: 12px;
        font-weight: 600;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    a.btn-link:hover {
        background-color: #0D47A1;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown('<div class="main-header">🔒 Sri Lanka Network Security Report Dashboard</div>', unsafe_allow_html=True)

# Introduction for students
with st.expander("📚 What is this dashboard about? (Click to learn!)", expanded=False):
    st.markdown("""
    ### Hello Young Explorers! 👋
    
    This dashboard shows how **safe and secure** different websites are in Sri Lanka.
    
    **Think of it like this:**
    - 🏰 Imagine websites are like houses
    - 🔒 Some houses have strong locks and security systems (SECURE ✅)
    - 🚪 Some houses have weak locks or broken doors (NOT SECURE ❌)
    
    **What we're checking:**
    1. **HTTPS** - Like a secret code that protects your information
    2. **Security Headers** - Like security cameras and alarm systems
    3. **Vulnerabilities** - Like holes in the fence that bad people could use
    
    **The Reports:**
    - **ac.lk** - Academic/University websites (schools and colleges)
    - **gov.lk** - Government websites (offices and services)
    
    Let's explore and see how safe these websites are! 🚀
    """)

# File paths
AC_FILE = "ac.lk_security_report.xlsx"
GOV_FILE = "gov.lk_security_report.xlsx"

# Optional: import the scanner to surface transparency information (checks, categories, etc.)
try:
    import security_scanner as scanner
except Exception:
    scanner = None

@st.cache_data
def load_data(file_path):
    """Load Excel data"""
    try:
        df = pd.read_excel(file_path)
        return df
    except Exception as e:
        st.error(f"Error loading {file_path}: {e}")
        return None

@st.cache_data
def list_excel_sheets(file_path: str) -> list[str]:
    """Return all sheet names in an Excel workbook."""
    try:
        xls = pd.ExcelFile(file_path)
        return xls.sheet_names
    except Exception as e:
        st.error(f"Error reading sheet names from {file_path}: {e}")
        return []

@st.cache_data
def load_excel_sheet(file_path: str, sheet_name: str) -> pd.DataFrame | None:
    """Load a specific sheet from the Excel workbook."""
    try:
        return pd.read_excel(file_path, sheet_name=sheet_name)
    except Exception as e:
        st.error(f"Error loading sheet '{sheet_name}' from {file_path}: {e}")
        return None

def make_clickable(df):
    """Convert URL- or domain-like columns to clickable links that open in a new tab.

    - Detects columns by name: url, link, domain, host, subdomain, website, site
    - If a cell value doesn't start with http(s), we prepend https:// by default
      (falls back to http:// when HTTPS Enabled column exists and is False for that row)
    """
    if df is None or len(df) == 0:
        return df

    df_display = df.copy()

    # Helper to normalize href
    def _normalize_href(val: str, row: pd.Series) -> str:
        if pd.isna(val):
            return val
        s = str(val).strip()
        if not s:
            return s
        # If already a full URL, use it as-is
        if re.match(r'^https?://', s, flags=re.IGNORECASE):
            href = s
        else:
            scheme = 'https'
            try:
                if 'HTTPS Enabled' in row.index and isinstance(row['HTTPS Enabled'], (bool, int)) and not bool(row['HTTPS Enabled']):
                    scheme = 'http'
            except Exception:
                pass
            href = f"{scheme}://{s}"
        # Display text remains the original value to keep table tidy
        return f'<a href="{href}" target="_blank" rel="noopener noreferrer" title="Click to visit {href}">{s}</a>'

    # Candidate column names to convert
    keywords = ['url', 'link', 'domain', 'host', 'subdomain', 'website', 'site']
    candidates = [c for c in df_display.columns if any(k in c.lower() for k in keywords)]

    # If we didn't find by name, try to detect columns with domain-like content (best-effort)
    if not candidates:
        for c in df_display.columns:
            sample_val = str(df_display[c].dropna().astype(str).head(1).tolist()[0]) if df_display[c].dropna().shape[0] else ''
            if re.search(r'([a-z0-9-]+\.)+[a-z]{2,}', sample_val, flags=re.IGNORECASE):
                candidates.append(c)

    for col in candidates:
        try:
            df_display[col] = df_display.apply(lambda row: _normalize_href(row[col], row), axis=1)
        except Exception:
            # Fall back to simple cell-wise apply if row-wise fails
            df_display[col] = df_display[col].apply(lambda x: f'<a href="{x}" target="_blank" rel="noopener noreferrer">{x}</a>' if pd.notna(x) else x)

    return df_display

def _get_query_params():
    """Return query params dict for current URL (supports older Streamlit)."""
    try:
        return dict(st.query_params)
    except Exception:
        return dict(st.experimental_get_query_params())

def _set_query_params(**kwargs):
    """Set/replace query params (supports older Streamlit)."""
    try:
        st.query_params.clear()
        st.query_params.update(kwargs)
    except Exception:
        st.experimental_set_query_params(**kwargs)

def display_clickable_table_with_details(df: pd.DataFrame, dataset_key: str, preferred_site_col: str | None = None):
    """Render a sortable table with:
    - Sort controls (column + order) applied server-side
    - Clickable URL/domain values
    - A per-row "Details" button that routes using query params to show filtered results
    """
    if df is None or df.empty:
        st.warning("No data to display")
        return

    # Determine site identifier column early (for search)
    site_col = preferred_site_col
    if not site_col:
        for c in ["Subdomain", "Domain", "domain", "host", "URL", "url", "Website", "Site"]:
            if c in df.columns:
                site_col = c
                break
    if not site_col:
        site_col = df.columns[0]

    # Search box
    st.markdown("#### 🔎 Find a website")
    search_col1, search_col2 = st.columns([3, 1])
    with search_col1:
        q = st.text_input("Type part of a URL/domain to filter", placeholder="e.g., pdn.ac.lk or gov.lk", key=f"search-{dataset_key}")
    with search_col2:
        search_all = st.checkbox("Search all columns", value=False, key=f"search-all-{dataset_key}")

    df_filtered = df
    if q:
        q_lower = str(q).strip()
        if search_all:
            mask = pd.Series(False, index=df.index)
            for c in df.columns:
                try:
                    mask = mask | df[c].astype(str).str.contains(q_lower, case=False, na=False)
                except Exception:
                    pass
            df_filtered = df[mask]
        else:
            if site_col in df.columns:
                df_filtered = df[df[site_col].astype(str).str.contains(q_lower, case=False, na=False)]

    # Choose default sort column
    all_cols = list(df_filtered.columns)
    default_sort_col = None
    for cand in ["Total_Score", "Score", "Safety Score", "HTTPS Enabled", preferred_site_col]:
        if cand in all_cols:
            default_sort_col = cand
            break
    if default_sort_col is None:
        default_sort_col = all_cols[0]

    col_a, col_b = st.columns([3,1])
    with col_a:
        sort_col = st.selectbox("Sort by", all_cols, index=all_cols.index(default_sort_col), key=f"sort-col-{dataset_key}")
    with col_b:
        sort_dir = st.radio("Order", ["Descending", "Ascending"], index=0, horizontal=True, key=f"sort-dir-{dataset_key}")

    df_sorted = df_filtered.sort_values(by=sort_col, ascending=(sort_dir == "Ascending"), kind="mergesort").reset_index(drop=True)

    # Build a display copy with clickable links
    df_display = make_clickable(df_sorted)

    # site_col already determined above

    # Add Details column with button-like links that set query params
    def _mk_details(val: str):
        if pd.isna(val):
            return ""
        s = str(val)
        query = urlparse.urlencode({"details": s, "ds": dataset_key})
        href = f"?{query}#details"
        return f'<a class="btn-link" href="{href}">Details</a>'

    df_display["Details"] = df_sorted[site_col].apply(_mk_details)

    # Reorder to place Details after site column if present
    cols = list(df_display.columns)
    if site_col in cols and "Details" in cols:
        cols.remove("Details")
        insert_at = cols.index(site_col) + 1
        cols.insert(insert_at, "Details")
        df_display = df_display[cols]

    # Render
    table_html = df_display.to_html(escape=False, index=False)
    st.markdown(f"<div class='dataframe-container'>{table_html}</div>", unsafe_allow_html=True)

    # Details section
    qp = _get_query_params()
    req_ds = qp.get("ds", [None])[0] if isinstance(qp.get("ds"), list) else qp.get("ds")
    req_site = qp.get("details", [None])[0] if isinstance(qp.get("details"), list) else qp.get("details")
    if req_ds == dataset_key and req_site:
        # Anchor target so the #details hash scrolls here
        st.markdown("<div id='details'></div>", unsafe_allow_html=True)
        st.markdown("---")
        st.markdown(f"## 🔎 Details for: {req_site}")
        mask = pd.Series(False, index=df_sorted.index)
        for c in [site_col, "URL", "Domain", "Subdomain", "host", "website", "site", "url"]:
            if c in df_sorted.columns:
                mask = mask | df_sorted[c].astype(str).str.contains(re.escape(req_site), case=False, na=False)
        filtered = df_sorted[mask]
        if filtered.empty:
            st.info("No matching rows found in this report.")
        else:
            # Build a concise summary card from the first matching row
            first = filtered.iloc[0]

            # Determine a score column if present
            score_col = None
            for sc in ["Total_Score", "Score", "Safety Score"]:
                if sc in filtered.columns:
                    score_col = sc
                    break

            https_enabled = None
            if "HTTPS Enabled" in filtered.columns:
                try:
                    https_enabled = bool(first["HTTPS Enabled"])
                except Exception:
                    https_enabled = None

            scan_success = None
            if "Scan_Success" in filtered.columns:
                scan_success = first["Scan_Success"]

            site_type = first["Type"] if "Type" in filtered.columns else None
            risk_rating = first["Risk_Rating"] if "Risk_Rating" in filtered.columns else None

            # Build a best-effort URL to open
            raw_url = None
            for c in ["URL", site_col, "Subdomain", "Domain", "host", "site"]:
                if c in filtered.columns and pd.notna(first.get(c)):
                    raw_url = str(first.get(c)).strip()
                    break
            target_url = None
            if raw_url:
                if raw_url.startswith("http://") or raw_url.startswith("https://"):
                    target_url = raw_url
                else:
                    scheme = "https" if https_enabled is True else "http"
                    target_url = f"{scheme}://{raw_url}"

            # Summary header row
            st.markdown("### 🧾 Summary")
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                if score_col is not None:
                    try:
                        st.metric("Safety/Score", f"{float(first[score_col]):.2f}")
                    except Exception:
                        st.metric("Safety/Score", str(first[score_col]))
                else:
                    st.metric("Rows", str(len(filtered)))
            with m2:
                if risk_rating is not None:
                    st.metric("Risk_Rating", str(risk_rating))
                elif site_type is not None:
                    st.metric("Type", str(site_type))
            with m3:
                if https_enabled is not None:
                    st.metric("HTTPS Enabled", "✅ True" if https_enabled else "❌ False")
                elif scan_success is not None:
                    st.metric("Scan_Success", str(scan_success))
            with m4:
                if scan_success is not None:
                    st.metric("Scan_Success", "✅ True" if bool(scan_success) else "❌ False")
                elif site_type is not None:
                    st.metric("Type", str(site_type))

            # Open website quick link
            if target_url:
                try:
                    st.link_button("Open website", target_url)
                except Exception:
                    st.markdown(f"<a class='btn-link' href='{target_url}' target='_blank' rel='noopener noreferrer'>Open website</a>", unsafe_allow_html=True)
            
            # Quick navigation to all sheets
            st.markdown("### 📑 Quick Navigation - Browse All Data Sheets")
            
            # Determine which file to check
            nav_file = None
            if "ac" in dataset_key.lower():
                nav_file = AC_FILE
            elif "gov" in dataset_key.lower():
                nav_file = GOV_FILE
            elif dataset_key == "all":
                nav_file = GOV_FILE if GOV_FILE else AC_FILE
            
            if nav_file:
                available_sheets = list_excel_sheets(nav_file)
                if available_sheets:
                    st.info(f"📊 Found {len(available_sheets)} data sheets available for this domain")
                    
                    # Create columns for sheet buttons
                    cols_per_row = 3
                    sheet_groups = [available_sheets[i:i + cols_per_row] for i in range(0, len(available_sheets), cols_per_row)]
                    
                    for sheet_group in sheet_groups:
                        cols = st.columns(len(sheet_group))
                        for idx, sheet_name in enumerate(sheet_group):
                            with cols[idx]:
                                # Create a unique anchor for each sheet
                                sheet_anchor = sheet_name.lower().replace(" ", "-")
                                if st.button(f"📄 {sheet_name}", key=f"nav-{dataset_key}-{sheet_name}", use_container_width=True):
                                    st.session_state[f"show_sheet_{sheet_anchor}"] = True

            # First, try to load ALL parameters from the "All Parameters" sheet
            st.markdown("### 📊 Complete Security Analysis - All 161+ Parameters")
            
            # Determine which file to search based on dataset_key
            search_file = None
            if "ac" in dataset_key.lower():
                search_file = AC_FILE
            elif "gov" in dataset_key.lower():
                search_file = GOV_FILE
            elif dataset_key == "all":
                # Try gov file first, then ac
                search_file = GOV_FILE if GOV_FILE else AC_FILE
            
            # Try to load the "All Parameters" sheet which has all 161 parameters
            all_params_loaded = False
            if search_file:
                try:
                    all_params_df = load_excel_sheet(search_file, "All Parameters")
                    if all_params_df is not None and not all_params_df.empty:
                        # Search for this domain in the All Parameters sheet
                        params_mask = pd.Series(False, index=all_params_df.index)
                        for col in all_params_df.columns:
                            try:
                                params_mask = params_mask | all_params_df[col].astype(str).str.contains(re.escape(req_site), case=False, na=False)
                            except Exception:
                                pass
                        
                        matched_params = all_params_df[params_mask]
                        if not matched_params.empty:
                            all_params_loaded = True
                            st.success(f"✅ Found complete security data with {len(matched_params.columns)} parameters!")
                            
                            # Get first row and transpose to show all parameters
                            if len(matched_params) > 0:
                                first_param_row = matched_params.iloc[0]
                                
                                # Create comprehensive parameter list
                                all_param_data = []
                                for param_name in matched_params.columns:
                                    param_value = first_param_row[param_name]
                                    
                                    # Format the value
                                    if pd.notna(param_value):
                                        if isinstance(param_value, bool):
                                            display_val = "✅ Pass" if param_value else "❌ Fail"
                                        elif isinstance(param_value, (int, float)):
                                            if param_name in ["Total_Score", "Score", "Safety Score"]:
                                                display_val = f"{param_value:.2f}"
                                            else:
                                                display_val = str(param_value)
                                        elif str(param_value).lower() in ['pass', 'true', 'yes']:
                                            display_val = f"✅ {param_value}"
                                        elif str(param_value).lower() in ['fail', 'false', 'no']:
                                            display_val = f"❌ {param_value}"
                                        else:
                                            display_val = str(param_value)
                                    else:
                                        display_val = "⚪ N/A"
                                    
                                    all_param_data.append({
                                        "Security Parameter": param_name,
                                        "Result": display_val
                                    })
                                
                                # Display the comprehensive parameter table
                                st.markdown(f"**Total Parameters Collected:** {len(all_param_data)}")
                                params_display_df = pd.DataFrame(all_param_data)
                                
                                # Add search functionality for the parameters
                                param_search = st.text_input("🔍 Search parameters (e.g., 'HTTPS', 'Header', 'SSL')", key=f"param-search-{dataset_key}")
                                if param_search:
                                    mask = params_display_df["Security Parameter"].str.contains(param_search, case=False, na=False) | \
                                           params_display_df["Result"].str.contains(param_search, case=False, na=False)
                                    params_display_df = params_display_df[mask]
                                    st.caption(f"Showing {len(params_display_df)} parameters matching '{param_search}'")
                                
                                # Display with pagination if too many
                                st.dataframe(
                                    params_display_df, 
                                    use_container_width=True, 
                                    hide_index=True,
                                    height=600  # Scrollable height
                                )
                                
                                # Download option
                                csv = params_display_df.to_csv(index=False)
                                st.download_button(
                                    label="📥 Download All Parameters as CSV",
                                    data=csv,
                                    file_name=f"{req_site}_all_parameters.csv",
                                    mime="text/csv"
                                )
                except Exception as e:
                    st.warning(f"Could not load 'All Parameters' sheet: {e}")
            
            # If we couldn't load from All Parameters sheet, show from current data
            if not all_params_loaded:
                st.info("Showing parameters from current sheet (limited view). Looking for 'All Parameters' sheet for complete data...")
                
                # Create a two-column layout for better readability
                detail_data = []
                for column in filtered.columns:
                    col_value = first[column]
                    if pd.notna(col_value):
                        # Format boolean values
                        if isinstance(col_value, bool):
                            display_value = "✅ True" if col_value else "❌ False"
                        # Format numeric values
                        elif isinstance(col_value, (int, float)):
                            if column in ["Total_Score", "Score", "Safety Score"]:
                                display_value = f"{col_value:.2f}" if isinstance(col_value, float) else str(col_value)
                            else:
                                display_value = str(col_value)
                        else:
                            display_value = str(col_value)
                    else:
                        display_value = "_No data_"
                    
                    detail_data.append({
                        "Parameter": column,
                        "Value": display_value
                    })
                
                # Display as a clean table
                details_df = pd.DataFrame(detail_data)
                st.dataframe(details_df, use_container_width=True, hide_index=True)
            
            # Load and display data from ALL sheets in the Excel file
            st.markdown("### 📚 Detailed Data from All Excel Sheets")
            st.info(f"🔍 Showing data for **{req_site}** from all available sheets")
            
            # Determine which file to search based on dataset_key
            search_file = None
            if "ac" in dataset_key.lower():
                search_file = AC_FILE
            elif "gov" in dataset_key.lower():
                search_file = GOV_FILE
            elif dataset_key == "all":
                # Search both files
                st.markdown("#### 🎓 Academic Report (ac.lk)")
                search_file = AC_FILE
            
            if search_file:
                all_sheets = list_excel_sheets(search_file)
                found_in_sheets = []
                sheets_with_data = []
                sheets_without_data = []
                
                for sheet_name in all_sheets:
                    sheet_df = load_excel_sheet(search_file, sheet_name)
                    if sheet_df is not None and not sheet_df.empty:
                        # Search for the domain in this sheet
                        sheet_mask = pd.Series(False, index=sheet_df.index)
                        for col in sheet_df.columns:
                            try:
                                sheet_mask = sheet_mask | sheet_df[col].astype(str).str.contains(re.escape(req_site), case=False, na=False)
                            except Exception:
                                pass
                        
                        matched_in_sheet = sheet_df[sheet_mask]
                        if not matched_in_sheet.empty:
                            found_in_sheets.append(sheet_name)
                            sheets_with_data.append((sheet_name, matched_in_sheet))
                        else:
                            sheets_without_data.append(sheet_name)
                
                # Show sheets with data
                if sheets_with_data:
                    st.success(f"✅ Found data in {len(sheets_with_data)} sheet(s)")
                    
                    for sheet_name, matched_data in sheets_with_data:
                        sheet_anchor = sheet_name.lower().replace(" ", "-")
                        
                        # Determine if this sheet should be expanded by default or by button click
                        is_expanded = (sheet_name in ["All Parameters", "Security Results", "Active Subdomains"]) or \
                                     st.session_state.get(f"show_sheet_{sheet_anchor}", False)
                        
                        with st.expander(f"📄 {sheet_name} ({len(matched_data)} rows, {len(matched_data.columns)} columns)", expanded=is_expanded):
                            st.caption(f"**Sheet:** {sheet_name} | **Rows:** {len(matched_data)} | **Columns:** {len(matched_data.columns)}")
                            
                            # Add download button for this sheet
                            csv_data = matched_data.to_csv(index=False)
                            st.download_button(
                                label=f"📥 Download {sheet_name} as CSV",
                                data=csv_data,
                                file_name=f"{req_site}_{sheet_name.replace(' ', '_')}.csv",
                                mime="text/csv",
                                key=f"download-{dataset_key}-{sheet_name}"
                            )
                            
                            # Display the data
                            st.dataframe(matched_data, use_container_width=True, hide_index=True, height=400)
                
                # Show sheets without data
                if sheets_without_data:
                    with st.expander(f"ℹ️ Sheets with no matching data ({len(sheets_without_data)})", expanded=False):
                        st.caption("These sheets exist but don't contain data for this specific domain:")
                        for sheet in sheets_without_data:
                            st.markdown(f"- 📄 {sheet}")
                
                if dataset_key == "all" and GOV_FILE:
                    # Also search gov.lk file
                    st.markdown("---")
                    st.markdown("#### 🏛️ Government Report (gov.lk)")
                    all_sheets_gov = list_excel_sheets(GOV_FILE)
                    found_in_gov = []
                    sheets_with_data_gov = []
                    sheets_without_data_gov = []
                    
                    for sheet_name in all_sheets_gov:
                        sheet_df = load_excel_sheet(GOV_FILE, sheet_name)
                        if sheet_df is not None and not sheet_df.empty:
                            # Search for the domain in this sheet
                            sheet_mask = pd.Series(False, index=sheet_df.index)
                            for col in sheet_df.columns:
                                try:
                                    sheet_mask = sheet_mask | sheet_df[col].astype(str).str.contains(re.escape(req_site), case=False, na=False)
                                except Exception:
                                    pass
                            
                            matched_in_sheet = sheet_df[sheet_mask]
                            if not matched_in_sheet.empty:
                                found_in_gov.append(sheet_name)
                                sheets_with_data_gov.append((sheet_name, matched_in_sheet))
                            else:
                                sheets_without_data_gov.append(sheet_name)
                    
                    if sheets_with_data_gov:
                        st.success(f"✅ Found data in {len(sheets_with_data_gov)} gov.lk sheet(s)")
                        
                        for sheet_name, matched_data in sheets_with_data_gov:
                            sheet_anchor = f"gov-{sheet_name.lower().replace(' ', '-')}"
                            is_expanded = (sheet_name in ["All Parameters", "Security Results", "Active Subdomains"]) or \
                                         st.session_state.get(f"show_sheet_{sheet_anchor}", False)
                            
                            with st.expander(f"📄 {sheet_name} ({len(matched_data)} rows, {len(matched_data.columns)} columns)", expanded=is_expanded):
                                st.caption(f"**Sheet:** {sheet_name} | **Rows:** {len(matched_data)} | **Columns:** {len(matched_data.columns)}")
                                
                                csv_data = matched_data.to_csv(index=False)
                                st.download_button(
                                    label=f"📥 Download {sheet_name} as CSV",
                                    data=csv_data,
                                    file_name=f"{req_site}_{sheet_name.replace(' ', '_')}_gov.csv",
                                    mime="text/csv",
                                    key=f"download-gov-{sheet_name}"
                                )
                                
                                st.dataframe(matched_data, use_container_width=True, hide_index=True, height=400)
                    
                    if sheets_without_data_gov:
                        with st.expander(f"ℹ️ Gov.lk sheets with no matching data ({len(sheets_without_data_gov)})", expanded=False):
                            st.caption("These sheets exist but don't contain data for this specific domain:")
                            for sheet in sheets_without_data_gov:
                                st.markdown(f"- 📄 {sheet}")
                
                # Summary of all sheets
                total_sheets_found = len(found_in_sheets) + (len(sheets_with_data_gov) if dataset_key == "all" and GOV_FILE else 0)
                if total_sheets_found > 0:
                    st.success(f"✅ Total: Found data in {total_sheets_found} sheet(s) across all reports")
                else:
                    st.warning("⚠️ No additional data found in other sheets for this domain.")
        st.button("Clear details", on_click=lambda: _set_query_params())

# Sidebar for navigation
st.sidebar.title("🧭 Navigation")
st.sidebar.markdown("Choose what you want to explore:")

page = st.sidebar.radio(
    "Select a Report:",
    [
        "🏠 Overview",
        "🎓 ac.lk Report (Universities)",
        "🏛️ gov.lk Report (Government)",
        "🌐 All Websites (Both)",
        "📊 Compare Both",
        "📖 Scoring Methodology",
        "🔍 Data Collection & Transparency"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("""
### 🎯 Quick Guide
- **Green** 🟢 = Safe & Secure
- **Yellow** 🟡 = Needs Attention
- **Red** 🔴 = Needs Urgent Fix
""")

st.sidebar.markdown("---")
st.sidebar.markdown("""
### 📊 How We Score
Click **"Scoring Methodology"** to learn how we rank websites and calculate security scores!
""")

# Function to explain security concepts
def explain_concept(concept):
    """Provide simple explanations for security concepts"""
    explanations = {
        "HTTPS": "🔒 **HTTPS** is like sending a secret letter in a locked box. Nobody can read it except the person you're sending it to!",
        "Security Headers": "🛡️ **Security Headers** are like rules that protect your house from intruders. They tell your computer how to stay safe when visiting a website.",
        "Vulnerabilities": "🚨 **Vulnerabilities** are like broken windows or weak locks that bad people could use to break in.",
        "SSL/TLS": "🔐 **SSL/TLS** is the technology that creates the secret code (encryption) to keep your information safe.",
        "HTTP": "📭 **HTTP** is like sending a postcard - anyone can read your message! Not very safe.",
    }
    return explanations.get(concept, "")

# Function to create a safety score
def calculate_safety_score(df):
    """Calculate overall safety score"""
    if df is None or len(df) == 0:
        return 0, "No Data"
    
    total_sites = len(df)
    safe_sites = 0
    
    # Check for HTTPS
    if 'HTTPS Enabled' in df.columns:
        safe_sites += df['HTTPS Enabled'].sum() if df['HTTPS Enabled'].dtype == 'bool' else 0
    
    score = (safe_sites / total_sites * 100) if total_sites > 0 else 0
    
    if score >= 80:
        return score, "Excellent! 🌟"
    elif score >= 60:
        return score, "Good, but can improve 👍"
    elif score >= 40:
        return score, "Needs attention ⚠️"
    else:
        return score, "Needs urgent improvement 🚨"

# Load data
ac_data = load_data(AC_FILE)
gov_data = load_data(GOV_FILE)

# OVERVIEW PAGE
if page == "🏠 Overview":
    st.markdown('<div class="sub-header">📊 Overall Security Overview</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎓 Academic Websites (ac.lk)")
        if ac_data is not None:
            ac_score, ac_status = calculate_safety_score(ac_data)
            st.metric("Total Websites Scanned", len(ac_data))
            st.metric("Safety Score", f"{ac_score:.1f}%", ac_status)
            
            # Create gauge chart
            fig_ac = go.Figure(go.Indicator(
                mode="gauge+number",
                value=ac_score,
                title={'text': "Safety Score"},
                gauge={'axis': {'range': [None, 100]},
                       'bar': {'color': "darkblue"},
                       'steps': [
                           {'range': [0, 40], 'color': "#FFCDD2"},
                           {'range': [40, 60], 'color': "#FFF9C4"},
                           {'range': [60, 80], 'color': "#C8E6C9"},
                           {'range': [80, 100], 'color': "#A5D6A7"}],
                       'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}))
            st.plotly_chart(fig_ac, use_container_width=True)
        else:
            st.warning("⚠️ Could not load ac.lk data")
    
    with col2:
        st.markdown("### 🏛️ Government Websites (gov.lk)")
        if gov_data is not None:
            gov_score, gov_status = calculate_safety_score(gov_data)
            st.metric("Total Websites Scanned", len(gov_data))
            st.metric("Safety Score", f"{gov_score:.1f}%", gov_status)
            
            # Create gauge chart
            fig_gov = go.Figure(go.Indicator(
                mode="gauge+number",
                value=gov_score,
                title={'text': "Safety Score"},
                gauge={'axis': {'range': [None, 100]},
                       'bar': {'color': "darkblue"},
                       'steps': [
                           {'range': [0, 40], 'color': "#FFCDD2"},
                           {'range': [40, 60], 'color': "#FFF9C4"},
                           {'range': [60, 80], 'color': "#C8E6C9"},
                           {'range': [80, 100], 'color': "#A5D6A7"}],
                       'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}))
            st.plotly_chart(fig_gov, use_container_width=True)
        else:
            st.warning("⚠️ Could not load gov.lk data")
    
    st.markdown("---")
    
    # Fun facts section
    st.markdown('<div class="sub-header">🎉 Did You Know?</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="info-box safe-box">
        <h4>🔒 HTTPS is Important!</h4>
        <p>When you see a lock icon 🔒 in your browser, it means your connection is secure!</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="info-box warning-box">
        <h4>🛡️ Security Headers</h4>
        <p>These are like invisible shields that protect websites from attacks!</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="info-box danger-box">
        <h4>⚠️ Be Safe Online!</h4>
        <p>Always check if a website is secure before entering personal information!</p>
        </div>
        """, unsafe_allow_html=True)

# AC.LK REPORT PAGE
elif page == "🎓 ac.lk Report (Universities)":
    st.markdown('<div class="sub-header">🎓 Academic Websites Security Report</div>', unsafe_allow_html=True)
    
    if ac_data is not None:
        st.markdown("### 📋 What are Academic Websites?")
        st.info("🏫 Academic websites belong to universities, colleges, and educational institutions in Sri Lanka. Students and teachers use these websites to access important information!")
        
        # Display basic statistics
        st.markdown("### 📊 Quick Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🌐 Total Websites", len(ac_data))
        
        with col2:
            if 'HTTPS Enabled' in ac_data.columns:
                https_count = ac_data['HTTPS Enabled'].sum() if ac_data['HTTPS Enabled'].dtype == 'bool' else 0
                st.metric("🔒 Secure (HTTPS)", https_count)
        
        with col3:
            if 'HTTPS Enabled' in ac_data.columns:
                http_count = len(ac_data) - https_count
                st.metric("📭 Not Secure (HTTP)", http_count)
        
        with col4:
            score, status = calculate_safety_score(ac_data)
            st.metric("✨ Safety Score", f"{score:.1f}%")
        
        # Explain HTTPS
        with st.expander("🔍 What does HTTPS mean?"):
            st.markdown(explain_concept("HTTPS"))
        
        # Show data table
        st.markdown("### 📑 Detailed Report")
        st.markdown("💡 **Tip:** Click the link in the Subdomain/URL column to open a website, or use the Details button to see all rows for that site.")
        
        # Display clickable + sortable table with Details buttons
        display_clickable_table_with_details(ac_data, dataset_key="ac", preferred_site_col="Subdomain" if "Subdomain" in ac_data.columns else None)
        
        # Visualizations
        st.markdown("### 📈 Visual Analysis")
        
        # HTTPS Distribution
        if 'HTTPS Enabled' in ac_data.columns:
            fig_https = px.pie(
                names=['Secure (HTTPS)', 'Not Secure (HTTP)'],
                values=[https_count, http_count],
                title="🔒 How many websites are secure?",
                color_discrete_sequence=['#4CAF50', '#F44336']
            )
            fig_https.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_https, use_container_width=True)
        
        # Additional columns analysis
        st.markdown("### � Browse Full Report (All Sheets)")
        ac_sheets = list_excel_sheets(AC_FILE)
        if ac_sheets:
            sel_ac_sheet = st.selectbox("Choose a sheet to view", ac_sheets, key="ac-sheet")
            df_sheet = load_excel_sheet(AC_FILE, sel_ac_sheet)
            if df_sheet is not None and not df_sheet.empty:
                # If it looks like a site list, render with clickable/details; else simple table
                site_col_guess = None
                for c in ["Subdomain", "URL", "Domain", "host", "site"]:
                    if c in df_sheet.columns:
                        site_col_guess = c
                        break
                st.caption(f"Sheet: {sel_ac_sheet} — {len(df_sheet)} rows")
                if site_col_guess:
                    display_clickable_table_with_details(df_sheet, dataset_key=f"ac-{sel_ac_sheet}", preferred_site_col=site_col_guess)
                else:
                    st.dataframe(df_sheet, use_container_width=True)
        else:
            st.info("No additional sheets found in the ac.lk report.")

        st.markdown("### �🔍 More Details")
        
        # Show all columns and their summaries
        for col in ac_data.columns:
            if col not in ['URL', 'Domain']:
                with st.expander(f"📊 {col}"):
                    if ac_data[col].dtype in ['int64', 'float64', 'bool']:
                        st.write(f"**Summary:** {ac_data[col].describe()}")
                        
                        # Create a bar chart for numeric columns
                        if ac_data[col].nunique() < 20:  # Only for columns with limited unique values
                            value_counts = ac_data[col].value_counts()
                            fig = px.bar(
                                x=value_counts.index,
                                y=value_counts.values,
                                labels={'x': col, 'y': 'Count'},
                                title=f"Distribution of {col}"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.write(ac_data[col].value_counts())
    else:
        st.error("❌ Could not load ac.lk report. Please make sure the file exists!")

# GOV.LK REPORT PAGE
elif page == "🏛️ gov.lk Report (Government)":
    st.markdown('<div class="sub-header">🏛️ Government Websites Security Report</div>', unsafe_allow_html=True)
    
    if gov_data is not None:
        st.markdown("### 📋 What are Government Websites?")
        st.info("🏛️ Government websites belong to Sri Lankan government offices and services. Citizens use these websites for important documents, information, and services!")
        
        # Display basic statistics
        st.markdown("### 📊 Quick Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🌐 Total Websites", len(gov_data))
        
        with col2:
            if 'HTTPS Enabled' in gov_data.columns:
                https_count = gov_data['HTTPS Enabled'].sum() if gov_data['HTTPS Enabled'].dtype == 'bool' else 0
                st.metric("🔒 Secure (HTTPS)", https_count)
        
        with col3:
            if 'HTTPS Enabled' in gov_data.columns:
                http_count = len(gov_data) - https_count
                st.metric("📭 Not Secure (HTTP)", http_count)
        
        with col4:
            score, status = calculate_safety_score(gov_data)
            st.metric("✨ Safety Score", f"{score:.1f}%")
        
        # Explain HTTPS
        with st.expander("🔍 What does HTTPS mean?"):
            st.markdown(explain_concept("HTTPS"))
        
        # Show data table
        st.markdown("### 📑 Detailed Report")
        st.markdown("💡 **Tip:** Click the link in the Subdomain/URL column to open a website, or use the Details button to see all rows for that site.")
        
        # Display clickable + sortable table with Details buttons
        display_clickable_table_with_details(gov_data, dataset_key="gov", preferred_site_col="Subdomain" if "Subdomain" in gov_data.columns else None)
        
        # Visualizations
        st.markdown("### 📈 Visual Analysis")
        
        # HTTPS Distribution
        if 'HTTPS Enabled' in gov_data.columns:
            fig_https = px.pie(
                names=['Secure (HTTPS)', 'Not Secure (HTTP)'],
                values=[https_count, http_count],
                title="🔒 How many websites are secure?",
                color_discrete_sequence=['#4CAF50', '#F44336']
            )
            fig_https.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_https, use_container_width=True)
        
        # Additional columns analysis
        st.markdown("### 📚 Browse Full Report (All Sheets)")
        gov_sheets = list_excel_sheets(GOV_FILE)
        if gov_sheets:
            sel_gov_sheet = st.selectbox("Choose a sheet to view", gov_sheets, key="gov-sheet")
            df_sheet = load_excel_sheet(GOV_FILE, sel_gov_sheet)
            if df_sheet is not None and not df_sheet.empty:
                site_col_guess = None
                for c in ["Subdomain", "URL", "Domain", "host", "site"]:
                    if c in df_sheet.columns:
                        site_col_guess = c
                        break
                st.caption(f"Sheet: {sel_gov_sheet} — {len(df_sheet)} rows")
                if site_col_guess:
                    display_clickable_table_with_details(df_sheet, dataset_key=f"gov-{sel_gov_sheet}", preferred_site_col=site_col_guess)
                else:
                    st.dataframe(df_sheet, use_container_width=True)
        else:
            st.info("No additional sheets found in the gov.lk report.")

        st.markdown("### 🔍 More Details")
        
        # Show all columns and their summaries
        for col in gov_data.columns:
            if col not in ['URL', 'Domain']:
                with st.expander(f"📊 {col}"):
                    if gov_data[col].dtype in ['int64', 'float64', 'bool']:
                        st.write(f"**Summary:** {gov_data[col].describe()}")
                        
                        # Create a bar chart for numeric columns
                        if gov_data[col].nunique() < 20:  # Only for columns with limited unique values
                            value_counts = gov_data[col].value_counts()
                            fig = px.bar(
                                x=value_counts.index,
                                y=value_counts.values,
                                labels={'x': col, 'y': 'Count'},
                                title=f"Distribution of {col}"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.write(gov_data[col].value_counts())
    else:
        st.error("❌ Could not load gov.lk report. Please make sure the file exists!")

# ALL WEBSITES (MERGED) PAGE
elif page == "🌐 All Websites (Both)":
    st.markdown('<div class="sub-header">🌐 All Sri Lankan Websites (ac.lk + gov.lk)</div>', unsafe_allow_html=True)

    frames = []
    if ac_data is not None:
        tmp = ac_data.copy()
        tmp["Source"] = "ac.lk"
        frames.append(tmp)
    if gov_data is not None:
        tmp = gov_data.copy()
        tmp["Source"] = "gov.lk"
        frames.append(tmp)

    if len(frames) == 0:
        st.error("❌ Could not load either report. Please ensure both Excel files exist.")
    else:
        all_df = pd.concat(frames, ignore_index=True, sort=False)

        # Quick stats
        st.markdown("### 📊 Quick Statistics (All)")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("🌐 Total Rows", len(all_df))
        with c2:
            st.metric("📁 Sources", ", ".join(sorted(all_df["Source"].unique())))
        with c3:
            if 'HTTPS Enabled' in all_df.columns and all_df['HTTPS Enabled'].dtype == 'bool':
                https_count = int(all_df['HTTPS Enabled'].sum())
                st.metric("🔒 Secure (HTTPS)", https_count)
        with c4:
            if 'HTTPS Enabled' in all_df.columns and all_df['HTTPS Enabled'].dtype == 'bool':
                not_https = int(len(all_df) - https_count)
                st.metric("📭 Not Secure (HTTP)", not_https)

        # Detailed table
        st.markdown("### 📑 Detailed Report (All)")
        st.markdown("💡 **Tip:** Use the search box to find a specific URL/domain. Click the link to open a site, or press Details to see all rows for that site.")

        display_clickable_table_with_details(all_df, dataset_key="all", preferred_site_col="Subdomain" if "Subdomain" in all_df.columns else None)

        # Optional: simple HTTPS distribution if column is available
        if 'HTTPS Enabled' in all_df.columns and all_df['HTTPS Enabled'].dtype == 'bool':
            st.markdown("### 📈 HTTPS Usage (All)")
            values = [https_count, not_https]
            fig = px.pie(
                names=['Secure (HTTPS)', 'Not Secure (HTTP)'],
                values=values,
                title="HTTPS vs HTTP across all sites",
                color_discrete_sequence=['#4CAF50', '#F44336']
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)

# COMPARISON PAGE
elif page == "📊 Compare Both":
    st.markdown('<div class="sub-header">📊 Comparing Academic vs Government Websites</div>', unsafe_allow_html=True)
    
    if ac_data is not None and gov_data is not None:
        st.markdown("### 🤔 Let's see which type of website is more secure!")
        
        # Initialize variables
        ac_https = 0
        gov_https = 0
        
        # Compare basic metrics
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🎓 Academic Websites")
            ac_score, ac_status = calculate_safety_score(ac_data)
            st.metric("Total Sites", len(ac_data))
            st.metric("Safety Score", f"{ac_score:.1f}%", ac_status)
            
            if 'HTTPS Enabled' in ac_data.columns:
                ac_https = ac_data['HTTPS Enabled'].sum() if ac_data['HTTPS Enabled'].dtype == 'bool' else 0
                ac_percentage = (ac_https / len(ac_data) * 100) if len(ac_data) > 0 else 0
                st.metric("Secure Sites", f"{ac_https} ({ac_percentage:.1f}%)")
        
        with col2:
            st.markdown("#### 🏛️ Government Websites")
            gov_score, gov_status = calculate_safety_score(gov_data)
            st.metric("Total Sites", len(gov_data))
            st.metric("Safety Score", f"{gov_score:.1f}%", gov_status)
            
            if 'HTTPS Enabled' in gov_data.columns:
                gov_https = gov_data['HTTPS Enabled'].sum() if gov_data['HTTPS Enabled'].dtype == 'bool' else 0
                gov_percentage = (gov_https / len(gov_data) * 100) if len(gov_data) > 0 else 0
                st.metric("Secure Sites", f"{gov_https} ({gov_percentage:.1f}%)")
        
        st.markdown("---")
        
        # Side-by-side comparison chart
        st.markdown("### 📊 Visual Comparison")
        
        comparison_data = pd.DataFrame({
            'Category': ['Academic', 'Government'],
            'Total Sites': [len(ac_data), len(gov_data)],
            'Secure Sites': [ac_https, gov_https],
            'Not Secure Sites': [len(ac_data) - ac_https, len(gov_data) - gov_https],
            'Safety Score': [ac_score, gov_score]
        })
        
        # Bar chart comparison
        fig1 = px.bar(
            comparison_data,
            x='Category',
            y=['Secure Sites', 'Not Secure Sites'],
            title="🔒 Secure vs Not Secure Websites",
            labels={'value': 'Number of Sites', 'variable': 'Status'},
            color_discrete_map={'Secure Sites': '#4CAF50', 'Not Secure Sites': '#F44336'},
            barmode='group'
        )
        st.plotly_chart(fig1, use_container_width=True)
        
        # Safety score comparison
        fig2 = px.bar(
            comparison_data,
            x='Category',
            y='Safety Score',
            title="✨ Safety Score Comparison",
            color='Safety Score',
            color_continuous_scale=['red', 'yellow', 'green']
        )
        # Show percentages above bars reliably using the y value
        fig2.update_traces(texttemplate='%{y:.1f}%', textposition='outside')
        fig2.update_layout(yaxis_range=[0, 100])
        st.plotly_chart(fig2, use_container_width=True)
        
        # Winner announcement
        st.markdown("### 🏆 And the winner is...")
        
        if ac_score > gov_score:
            st.success(f"🎓 **Academic websites are more secure!** They have a safety score of {ac_score:.1f}% compared to {gov_score:.1f}% for government websites.")
        elif gov_score > ac_score:
            st.success(f"🏛️ **Government websites are more secure!** They have a safety score of {gov_score:.1f}% compared to {ac_score:.1f}% for academic websites.")
        else:
            st.info("🤝 **It's a tie!** Both academic and government websites have the same safety score.")
        
        # Educational note
        st.markdown("---")
        st.markdown("### 💡 What does this mean?")
        st.info("""
        **Remember:** A higher safety score means more websites are using HTTPS and other security features.
        This is important because it keeps your information safe when you visit these websites!
        
        Both types of websites should work hard to improve their security to protect all users! 🛡️
        """)
        
    else:
        st.error("❌ Could not load one or both reports. Please make sure both files exist!")

# SCORING METHODOLOGY PAGE
elif page == "📖 Scoring Methodology":
    st.markdown('<div class="sub-header">📖 How We Rank Websites & Calculate Scores</div>', unsafe_allow_html=True)
    
    st.markdown("### 🤔 How Do We Know If a Website is Safe?")
    
    st.info("""
    **For Grade 5 Students:** 
    Think of website security like checking if your house is safe. We look at different things like:
    - 🔒 Does it have strong locks? (HTTPS)
    - 🚪 Are the doors secure? (Security Headers)
    - 🛡️ Does it have an alarm system? (Security Features)
    - ⚠️ Are there any broken windows? (Vulnerabilities)
    """)
    
    # Main scoring explanation
    st.markdown("---")
    st.markdown("## 📊 Our Scoring System")
    
    # Create tabs for different aspects
    tab1, tab2, tab3, tab4 = st.tabs([
        "🎯 Overall Score", 
        "🔒 What We Check", 
        "📈 Ranking System",
        "🧮 Score Calculation"
    ])
    
    with tab1:
        st.markdown("### 🎯 Overall Safety Score")
        st.markdown("""
        We give each website a **Safety Score** from **0% to 100%**.
        
        Think of it like a test score in school:
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            #### 📊 Score Ranges
            
            | Score | Grade | Meaning |
            |-------|-------|---------|
            | 80-100% | 🌟 Excellent | Very Safe! |
            | 60-79% | 👍 Good | Pretty Safe, Can Improve |
            | 40-59% | ⚠️ Fair | Needs Attention |
            | 0-39% | 🚨 Poor | Needs Urgent Fix |
            """)
        
        with col2:
            # Create a sample gauge chart
            fig_sample = go.Figure(go.Indicator(
                mode="gauge+number",
                value=75,
                title={'text': "Example: 75% Safety Score"},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 40], 'color': "#FFCDD2"},
                        {'range': [40, 60], 'color': "#FFF9C4"},
                        {'range': [60, 80], 'color': "#C8E6C9"},
                        {'range': [80, 100], 'color': "#A5D6A7"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            fig_sample.update_layout(height=300)
            st.plotly_chart(fig_sample, use_container_width=True)
        
        st.markdown("---")
        st.markdown("### 💡 What Does This Mean?")
        st.success("""
        **A website with 80% score** = 8 out of 10 security checks passed! 🎉
        
        **A website with 40% score** = Only 4 out of 10 security checks passed. Needs work! ⚠️
        """)
    
    with tab2:
        st.markdown("### 🔒 Security Features We Check")
        st.markdown("""
        Our security scanner checks many things to keep you safe. Here are the main ones:
        """)
        
        # Security checks with explanations
        security_checks = [
            {
                "icon": "🔒",
                "name": "HTTPS Enabled",
                "kid_explanation": "Like sending a secret letter in a locked box",
                "technical": "Checks if the website uses SSL/TLS encryption",
                "importance": "HIGH",
                "points": "25 points"
            },
            {
                "icon": "🛡️",
                "name": "Security Headers",
                "kid_explanation": "Special rules that protect your computer",
                "technical": "Checks for headers like Content-Security-Policy, X-Frame-Options, etc.",
                "importance": "HIGH",
                "points": "20 points"
            },
            {
                "icon": "🔐",
                "name": "SSL/TLS Certificate",
                "kid_explanation": "Like an ID card for websites",
                "technical": "Validates SSL certificate strength and expiration",
                "importance": "HIGH",
                "points": "20 points"
            },
            {
                "icon": "🚫",
                "name": "No Vulnerabilities",
                "kid_explanation": "No broken windows or weak spots",
                "technical": "Scans for common vulnerabilities (XSS, SQL Injection, etc.)",
                "importance": "CRITICAL",
                "points": "25 points"
            },
            {
                "icon": "🔄",
                "name": "HTTP to HTTPS Redirect",
                "kid_explanation": "Automatically switches to the safe version",
                "technical": "Checks if HTTP requests redirect to HTTPS",
                "importance": "MEDIUM",
                "points": "10 points"
            }
        ]
        
        for check in security_checks:
            with st.expander(f"{check['icon']} {check['name']} - {check['importance']} Priority"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**For Kids:** {check['kid_explanation']}")
                    st.markdown(f"**Technical:** {check['technical']}")
                
                with col2:
                    importance_color = {
                        "CRITICAL": "🔴",
                        "HIGH": "🟠",
                        "MEDIUM": "🟡",
                        "LOW": "🟢"
                    }
                    st.metric("Worth", check['points'])
                    st.markdown(f"{importance_color[check['importance']]} {check['importance']}")
        
        st.markdown("---")
        st.info("💡 **Total Points:** 100 points = 100% Safety Score")
    
    with tab3:
        st.markdown("### 📈 How We Rank Websites")
        
        st.markdown("""
        We compare all websites and rank them from best to worst based on their safety scores.
        
        #### 🏅 Ranking Process:
        """)
        
        steps = [
            ("1️⃣", "Scan the Website", "Our scanner visits each website and checks all security features"),
            ("2️⃣", "Count Security Features", "We count how many security features are working"),
            ("3️⃣", "Calculate Score", "We add up points for each security feature (max 100 points)"),
            ("4️⃣", "Compare Websites", "We compare all websites and sort them by score"),
            ("5️⃣", "Assign Rank", "Highest score = Rank #1 (Best!), Lowest score = Last rank")
        ]
        
        for emoji, title, description in steps:
            st.markdown(f"""
            <div class="info-box safe-box">
                <h4>{emoji} {title}</h4>
                <p>{description}</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("### 🏆 Example Ranking")
        
        # Create example ranking table
        example_data = pd.DataFrame({
            'Rank': ['🥇 1st', '🥈 2nd', '🥉 3rd', '4th', '5th'],
            'Website': ['university-a.ac.lk', 'university-b.ac.lk', 'university-c.ac.lk', 'university-d.ac.lk', 'university-e.ac.lk'],
            'Safety Score': ['95%', '87%', '76%', '62%', '45%'],
            'Grade': ['🌟 Excellent', '🌟 Excellent', '👍 Good', '👍 Good', '⚠️ Fair'],
            'HTTPS': ['✅', '✅', '✅', '✅', '❌'],
            'Security Headers': ['✅', '✅', '✅', '⚠️', '❌'],
            'SSL Certificate': ['✅', '✅', '✅', '✅', '⚠️']
        })
        
        st.dataframe(example_data, use_container_width=True, hide_index=True)
        
        st.success("🎯 **University A** is ranked #1 because it has the highest safety score (95%)!")
    
    with tab4:
        st.markdown("### 🧮 How We Calculate the Score")
        
        st.markdown("""
        Let's break down exactly how we calculate the safety score step by step!
        """)
        
        st.markdown("---")
        st.markdown("#### 📝 Step-by-Step Calculation")
        
        st.markdown("""
        **Example: Checking university-example.ac.lk**
        
        We check each security feature and give points:
        """)
        
        calculation_example = pd.DataFrame({
            'Security Check': [
                '🔒 HTTPS Enabled',
                '🛡️ Security Headers (8 headers)',
                '🔐 Strong SSL Certificate',
                '🚫 No Vulnerabilities Found',
                '🔄 HTTP Redirects to HTTPS',
                '---',
                '**TOTAL SCORE**'
            ],
            'Status': [
                '✅ Yes',
                '⚠️ 6 out of 8',
                '✅ Valid & Strong',
                '⚠️ 2 minor issues',
                '✅ Yes',
                '---',
                '---'
            ],
            'Points Earned': [
                '25 / 25',
                '15 / 20',
                '20 / 20',
                '18 / 25',
                '10 / 10',
                '---',
                '**88 / 100**'
            ],
            'Explanation': [
                'Perfect! Using HTTPS',
                'Missing 2 headers',
                'Perfect! Valid certificate',
                'Found 2 small problems',
                'Perfect! Auto-redirects',
                '---',
                '**88% = Excellent! 🌟**'
            ]
        })
        
        st.dataframe(calculation_example, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.markdown("#### 🎓 Understanding the Math")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            **Simple Formula:**
            ```
            Safety Score = (Points Earned ÷ Total Points) × 100
            
            Example:
            = (88 ÷ 100) × 100
            = 88%
            ```
            """)
        
        with col2:
            st.markdown("""
            **What It Means:**
            
            - ✅ **25/25** = Perfect score!
            - ⚠️ **15/20** = Good but can improve
            - ❌ **0/25** = Big problem, needs fixing!
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Real-World Impact")
        
        impact_col1, impact_col2, impact_col3 = st.columns(3)
        
        with impact_col1:
            st.markdown("""
            <div class="info-box safe-box">
                <h4>🌟 90-100% Score</h4>
                <p><strong>Impact:</strong> Your data is very safe! The website has excellent security.</p>
                <p><strong>Risk Level:</strong> Very Low 🟢</p>
            </div>
            """, unsafe_allow_html=True)
        
        with impact_col2:
            st.markdown("""
            <div class="info-box warning-box">
                <h4>⚠️ 50-70% Score</h4>
                <p><strong>Impact:</strong> Some security is in place, but there are gaps that hackers could use.</p>
                <p><strong>Risk Level:</strong> Medium 🟡</p>
            </div>
            """, unsafe_allow_html=True)
        
        with impact_col3:
            st.markdown("""
            <div class="info-box danger-box">
                <h4>🚨 Below 50% Score</h4>
                <p><strong>Impact:</strong> Your data could be at risk! Be very careful entering personal information.</p>
                <p><strong>Risk Level:</strong> High 🔴</p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Additional resources
    st.markdown("## 📚 Learn More")
    
    resource_col1, resource_col2 = st.columns(2)
    
    with resource_col1:
        st.markdown("""
        ### 🎓 For Students
        
        Want to learn more about internet security?
        
        - **Look for the lock icon** 🔒 in your browser
        - **Check if URL starts with HTTPS** not HTTP
        - **Never share passwords** on unsecure websites
        - **Tell an adult** if you see warnings about security
        """)
    
    with resource_col2:
        st.markdown("""
        ### 👨‍💻 For Technical Users
        
        Our scanner uses industry-standard tools:
        
        - **SSLyze** for SSL/TLS analysis
        - **Security Headers** validation (OWASP guidelines)
        - **DNS** security checks
        - **Vulnerability scanning** (OWASP Top 10)
        - **Compliance checks** (best practices)
        """)
    
    st.markdown("---")
    
    # Fun quiz
    with st.expander("🎮 Test Your Knowledge! (Quick Quiz)"):
        st.markdown("### Quick Security Quiz!")
        
        q1 = st.radio(
            "1. What does HTTPS mean?",
            ["Hyper Text Transfer Protocol Secure", "Happy Typing Protocol", "High Tech Protection System"],
            index=None
        )
        
        if q1 == "Hyper Text Transfer Protocol Secure":
            st.success("✅ Correct! HTTPS means the connection is secure!")
        elif q1 is not None:
            st.error("❌ Try again! Think about 'Secure'...")
        
        q2 = st.radio(
            "2. Which safety score is better?",
            ["35%", "75%", "50%"],
            index=None
        )
        
        if q2 == "75%":
            st.success("✅ Correct! Higher scores mean better security!")
        elif q2 is not None:
            st.error("❌ Remember: higher scores = safer websites!")
        
        q3 = st.radio(
            "3. What should you look for in your browser to know a site is secure?",
            ["A lock icon 🔒", "A smiley face 😊", "A star ⭐"],
            index=None
        )
        
        if q3 == "A lock icon 🔒":
            st.success("✅ Excellent! Always look for the lock icon!")
            st.balloons()
        elif q3 is not None:
            st.error("❌ Look for the lock icon in your browser's address bar!")

# TRANSPARENCY PAGE
elif page == "🔍 Data Collection & Transparency":
    st.markdown('<div class="sub-header">🔍 How We Collect Data & What We Publish</div>', unsafe_allow_html=True)

    st.markdown("""
    This page explains, in plain language, how the scanner gathers information, which Python
    packages it uses, what parameters are collected, and why. Our goal is to be transparent
    and responsible with every result we show on this dashboard.
    """)

    # High-level workflow
    st.markdown("### 🧭 End-to-end workflow")
    st.markdown("""
    1. Discover subdomains (5-layer strategy):
       - Certificate Transparency search (crt.sh)
       - Public datasets (HackerTarget, ThreatCrowd)
       - Smart DNS probing (~18,953 patterns: a-z, aa-zz, aaa-zzz, numbers, common words)
       - www vs non-www variants for each host
       - HTTP/HTTPS availability checks
    2. Classify each host: webapp, api, static, or other
    3. Run context-aware security checks (only those relevant for the type)
    4. Compute a weighted score and Risk_Rating
    5. Save results to Excel with evidence and coverage sheets
    6. This dashboard reads those Excel files and visualizes them
    """)

    # Packages used and capabilities
    st.markdown("### 📦 Python packages and what they do")
    pkgs = [
        ("pandas", "Data processing and Excel I/O"),
        ("openpyxl", "Efficient incremental updates to Excel workbooks"),
        ("requests", "HTTPS/HTTP requests to fetch pages and headers"),
        ("beautifulsoup4", "HTML parsing for things like SRI checks"),
        ("sslyze", "TLS/SSL analysis: protocol support, ciphers, HSTS header via scan"),
        ("dnspython", "DNS queries for SPF/DNSSEC/MX/CAA and resolution"),
        ("socket", "Basic DNS resolution (getaddrinfo) for liveness"),
        ("tqdm", "Progress bars during scanning"),
        ("concurrent.futures", "Parallel DNS/probing to speed up discovery"),
        ("argparse/json", "CLI arguments and optional evidence JSON parsing"),
        ("streamlit + plotly", "This dashboard UI and charts")
    ]
    cols = st.columns(2)
    half = (len(pkgs) + 1) // 2
    with cols[0]:
        for name, purpose in pkgs[:half]:
            st.markdown(f"- **{name}** — {purpose}")
    with cols[1]:
        for name, purpose in pkgs[half:]:
            st.markdown(f"- **{name}** — {purpose}")

    # Parameters collected (controls)
    st.markdown("### 🧪 Parameters we collect (security controls)")
    if scanner and hasattr(scanner, "CHECKS"):
        # Build mapping: control -> category
        cat_by_control = {}
        if hasattr(scanner, "CATEGORIES"):
            for cat, info in scanner.CATEGORIES.items():
                for cid in info.get("checks", []):
                    cat_by_control[cid] = cat

        # Build DataFrame of controls
        checks_rows = []
        for cid, meta in scanner.CHECKS.items():
            checks_rows.append({
                "Control_ID": cid,
                "Priority": meta.get("priority", ""),
                "Description": meta.get("desc", ""),
                "Category": cat_by_control.get(cid, "(derived)")
            })
        df_checks = pd.DataFrame(checks_rows).sort_values(["Category", "Priority", "Control_ID"]).reset_index(drop=True)

        # Filters
        f1, f2 = st.columns([2, 2])
        with f1:
            sel_cat = st.multiselect("Filter by category", sorted({r["Category"] for r in checks_rows if r["Category"]}))
        with f2:
            sel_pri = st.multiselect("Filter by priority", sorted({r["Priority"] for r in checks_rows if r["Priority"]}))
        q = st.text_input("Search (ID/description)", key="search-controls")

        df_show = df_checks
        if sel_cat:
            df_show = df_show[df_show["Category"].isin(sel_cat)]
        if sel_pri:
            df_show = df_show[df_show["Priority"].isin(sel_pri)]
        if q:
            ql = q.strip().lower()
            df_show = df_show[df_show.apply(lambda r: ql in str(r["Control_ID"]).lower() or ql in str(r["Description"]).lower(), axis=1)]

        st.dataframe(df_show, use_container_width=True, hide_index=True)
        st.caption("Each control is a parameter we attempt to verify. Relevant controls depend on the host type (webapp/api/static/other).")
    else:
        st.info("Scanner metadata not available for import. We’ll still show high-level information.")

    # What fields go into the Excel reports
    st.markdown("### 📁 What we save to reports")
    st.markdown("""
    Core columns (in Security Results / Active / Inactive sheets):
    - Subdomain — the exact host tested (www and non-www variants)
    - Type — detected host type (webapp, api, static, other)
    - Scan_Success — whether HTTPS connection succeeded for header checks
    - Total_Score — weighted score out of 100 (type-aware)
    - Risk_Rating — Critical / High / Medium / Low (type-aware thresholds)

    Additional evidence sheets include:
    - All Parameters — every control result per subdomain (Pass/Fail/N/A)
    - Data Collection Evidence — how many checks were performed, pass/fail counts
    - Parameter Coverage Summary — pass rates across all subdomains
    - Discovery Stats, Technologies — discovery and stack summaries (when auto-enumeration was used)
    """)

    # Standards mapping (if available)
    if scanner and hasattr(scanner, "STANDARDS"):
        st.markdown("### 📚 Standards mapping (approximate)")
        rows = []
        for std, controls in scanner.STANDARDS.items():
            rows.append({"Standard": std, "Controls_Mapped": len(controls)})
        st.dataframe(pd.DataFrame(rows).sort_values("Standard"), use_container_width=True, hide_index=True)

    # Evidence JSON example
    if scanner and hasattr(scanner, "SAMPLE_EVIDENCE_JSON"):
        with st.expander("📄 Sample evidence JSON (optional, for program/compliance checks)"):
            st.json(scanner.SAMPLE_EVIDENCE_JSON)

    # Responsible scanning notes
    st.markdown("### 🧑‍⚖️ Responsible scanning & limitations")
    st.markdown("""
    - Read-only checks: we use standard HTTPS requests and DNS queries; no credential brute-force, no exploitation.
    - Rate limiting: ~3 seconds between scans to reduce load on sites.
    - Timeouts: Conservative timeouts and robust error handling to avoid long-hanging requests.
    - Public data sources: Certificate Transparency logs and open APIs complement domain patterns.
    - Best-effort classification: Host type detection is heuristic and may misclassify some sites.
    - TLS scanning uses sslyze; some environments may restrict or block these probes.
    - Results reflect the moment of scanning; security settings change over time.
    """)

    st.success("Transparency: All scores and rankings are derived from the checks above. Where a check isn’t applicable to a host type, it’s excluded from scoring.")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #757575; padding: 20px;'>
    <p>🔒 <strong>Stay Safe Online!</strong> 🔒</p>
    <p>Always check if a website is secure before entering your personal information.</p>
    <p>Made with ❤️ for learning about internet security</p>
</div>
""", unsafe_allow_html=True)
