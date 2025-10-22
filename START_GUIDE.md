# start.sh - Automated Security Scanner

## Quick Start

**Option 1: Run Normally (stay connected)**
```bash
bash start.sh
```

**Option 2: Run in Background (safe to disconnect SSH)**
```bash
# Start the scan
nohup bash start.sh &

# Or just run it normally - it will log to file automatically
bash start.sh

# Then disconnect SSH - scans will continue running!
```

**Check Status After Reconnecting:**
```bash
bash check_status.sh
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
- `start_run_YYYYMMDD_HHMMSS.log` - Main execution log
- `ac_lk_scan_YYYYMMDD_HHMMSS.log` - Detailed ac.lk scan log (temporary)
- `gov_lk_scan_YYYYMMDD_HHMMSS.log` - Detailed gov.lk scan log (temporary)

## Running Safely Over SSH

The script is **SSH-disconnect safe**! You can start it and disconnect without interrupting the scans.

### How It Works

1. **Automatic Logging** - All output is saved to timestamped log files
2. **Background Processes** - Scans use `nohup` to survive SSH disconnection
3. **PID Tracking** - Process IDs are saved for monitoring
4. **Status Checking** - Use `check_status.sh` to monitor progress anytime

### Workflow

```bash
# On server: Start the scan
bash start.sh

# You'll see: "📝 Logging to: start_run_20251022_143000.log"
# Scans will continue even if you disconnect

# Disconnect SSH (close terminal, network drops, etc.)
# Scans keep running in the background!

# Later: Reconnect and check status
bash check_status.sh

# View live progress
tail -f ac_lk_scan_*.log
tail -f gov_lk_scan_*.log

# View main log
tail -f start_run_*.log
```

### Alternative: Using screen or tmux

If you prefer session management tools:

```bash
# Using screen
screen -S security_scan
bash start.sh
# Press Ctrl+A then D to detach
# Reconnect: screen -r security_scan

# Using tmux
tmux new -s security_scan
bash start.sh
# Press Ctrl+B then D to detach
# Reconnect: tmux attach -t security_scan
```

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
- Use the status checker: `bash check_status.sh`
- Or check the log files while scans are running:
  ```bash
  tail -f ac_lk_scan_*.log
  # or
  tail -f gov_lk_scan_*.log
  # or main log
  tail -f start_run_*.log
  ```
- Scan logs are auto-deleted after successful completion
- Main log is always preserved

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
