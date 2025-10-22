# start.sh - Automated Security Scanner

## Quick Start

```bash
./start.sh
```

That's it! The script will handle everything automatically.

## What It Does

1. **Checks for Updates** 🔄
   - Fetches latest code from GitHub
   - Pulls updates if available
   - Continues with local version if already up-to-date

2. **Sets Up Python Environment** 🐍
   - Checks if `venv` directory exists
   - Creates new virtual environment if not found
   - Installs dependencies from `requirements.txt` (first time only)
   - Activates the virtual environment
   - Verifies Python is ready

3. **Runs Security Scans** 🔍
   - Scans `ac.lk` and `gov.lk` **simultaneously** (parallel execution)
   - Both scans run in the background
   - Generates Excel reports for each
   - Creates temporary log files during scanning
   - Waits for both scans to complete
   - Cleans up logs if both succeed

4. **Pushes Results** 📤
   - Commits both report files
   - Uses timestamp as commit message (e.g., "2025-10-22 14:30:00 successfully run")
   - Pushes to GitHub

## Output Files

- `ac.lk_security_report.xlsx` - Complete security analysis of ac.lk
- `gov.lk_security_report.xlsx` - Complete security analysis of gov.lk

## Scheduling (Optional)

To run automatically every day at 2 AM:

```bash
# Open crontab editor
crontab -e

# Add this line (adjust path as needed):
0 2 * * * cd /Users/lalithk90/Desktop/Reseach_work/ac-lk-network-audit && ./start.sh >> scan.log 2>&1
```

Or use launchd on macOS for better integration.

## Error Handling

The script will:
- Exit immediately if any step fails
- Show colored error messages
- Not commit/push if scans fail

## Requirements

- Git configured with SSH or HTTPS credentials
- Python 3.8+ installed
- Dependencies will be installed automatically on first run

## First Run

On the first run, the script will:
1. Create a `venv` directory
2. Install all dependencies from `requirements.txt`
3. This takes a few minutes (one-time setup)

Subsequent runs will skip this step and just activate the existing environment.

## Logs

To save output to a log file:

```bash
./start.sh 2>&1 | tee scan_$(date +%Y%m%d_%H%M%S).log
```

## Troubleshooting

**"python3: command not found"**
- Install Python 3.8 or higher
- macOS: `brew install python3`
- Check: `python3 --version`

**"ModuleNotFoundError" after creating venv**
- Delete the venv directory: `rm -rf venv`
- Run start.sh again to recreate and reinstall dependencies

**"fatal: could not read Username"**
- Configure Git credentials
- Use SSH keys or credential helper

**Scan takes too long**
- Scans now run in parallel, cutting total time roughly in half
- ac.lk and gov.lk scan simultaneously
- Still expect 2-3 hours total (depends on slowest scan)
- Consider running overnight via cron

**Want to see scan progress**
- Check the temporary log files while scans are running:
  ```bash
  tail -f ac_lk_scan_*.log
  # or
  tail -f gov_lk_scan_*.log
  ```
- Logs are auto-deleted after successful completion

**Git push fails**
- Check network connection
- Verify you have push access to the repository
- Check if you need to resolve merge conflicts

## Tips

- Run manually first to verify everything works
- Check the generated reports before setting up automation
- Monitor the first few automated runs
- Consider adding email notifications on completion/failure
- Parallel execution reduces total scan time significantly
- Both scans share the same environment and resources
- If one scan fails, both logs are preserved for debugging
