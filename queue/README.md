# Queue Management System

Sequential domain processing with persistent state.

## Files

- **`domain_queue_manager.py`** - CLI utility for queue operations
- **`domain_queue.json`** - Persistent queue state (auto-created)

## Commands

```bash
# Initialize queue
python queue/domain_queue_manager.py init domain1.com domain2.com

# Get next domain
python queue/domain_queue_manager.py next

# Mark completed
python queue/domain_queue_manager.py complete domain.com

# Mark failed
python queue/domain_queue_manager.py fail domain.com "error_message"

# Add discovered subdomains
python queue/domain_queue_manager.py add sub1.com sub2.com

# Check status
python queue/domain_queue_manager.py status

# Clear queue
python queue/domain_queue_manager.py clear

# Interactive mode
python queue/domain_queue_manager.py
```

## Integration

- **`start.sh`** - Uses queue for sequential domain processing
- **`src/security_scanner.py`** - Auto-adds discovered subdomains to queue

## Queue State

`domain_queue.json` contains:
- `domains` - Pending domains to scan
- `completed` - Successfully scanned domains
- `failed` - Failed domains with error messages
