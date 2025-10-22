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

2. **Activates Environment** 🐍
   - Activates conda `mri_data` environment
   - Verifies Python is ready

3. **Runs Security Scans** 🔍
   - Scans `ac.lk` domain (all subdomains)
   - Scans `gov.lk` domain (all subdomains)
   - Generates Excel reports for each

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
- Conda with `mri_data` environment
- All dependencies installed in the environment (see `requirements.txt`)

## Logs

To save output to a log file:

```bash
./start.sh 2>&1 | tee scan_$(date +%Y%m%d_%H%M%S).log
```

## Troubleshooting

**"conda: command not found"**
- Make sure conda is in your PATH
- Try: `source ~/anaconda3/etc/profile.d/conda.sh` (adjust path)

**"fatal: could not read Username"**
- Configure Git credentials
- Use SSH keys or credential helper

**Scan takes too long**
- This is normal for large domains (2-3 hours each)
- Consider running overnight via cron

**Git push fails**
- Check network connection
- Verify you have push access to the repository
- Check if you need to resolve merge conflicts

## Tips

- Run manually first to verify everything works
- Check the generated reports before setting up automation
- Monitor the first few automated runs
- Consider adding email notifications on completion/failure
