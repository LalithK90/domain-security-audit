#!/usr/bin/env python3
"""Domain queue manager - handles domain queue for sequential processing with proper state management."""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

QUEUE_FILE = Path(__file__).parent / 'domain_queue.json'


def load_queue() -> Dict[str, Any]:
    """Load domain queue from JSON file."""
    if not QUEUE_FILE.exists():
        return {'domains': [], 'completed': [], 'failed': []}
    try:
        with open(QUEUE_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading queue: {e}")
        return {'domains': [], 'completed': [], 'failed': []}


def save_queue(queue: Dict[str, Any]) -> bool:
    """Save domain queue to JSON file."""
    try:
        with open(QUEUE_FILE, 'w') as f:
            json.dump(queue, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ Error saving queue: {e}")
        return False


def initialize_queue(domains: List[str]) -> bool:
    """Initialize queue with list of domains to process."""
    # Normalize domain names
    normalized = [d.strip().lower() for d in domains if d.strip()]
    
    if not normalized:
        print("❌ No valid domains provided")
        return False
    
    queue = {
        'domains': normalized,
        'completed': [],
        'failed': []
    }
    
    if save_queue(queue):
        print(f"\n✅ Domain queue initialized with {len(normalized)} domain(s):")
        for i, domain in enumerate(normalized, 1):
            print(f"   {i}. {domain}")
        return True
    return False


def get_next_domain() -> Optional[str]:
    """Get next domain from queue without removing it."""
    queue = load_queue()
    if queue['domains']:
        return queue['domains'][0]
    return None


def complete_domain(domain: str) -> bool:
    """Mark domain as completed and remove from queue."""
    queue = load_queue()
    
    if domain in queue['domains']:
        queue['domains'].remove(domain)
        queue['completed'].append(domain)
        return save_queue(queue)
    
    return False


def fail_domain(domain: str, error: str = "") -> bool:
    """Mark domain as failed and remove from queue."""
    queue = load_queue()
    
    if domain in queue['domains']:
        queue['domains'].remove(domain)
        queue['failed'].append({'domain': domain, 'error': error})
        return save_queue(queue)
    
    return False


def get_queue_status() -> Dict[str, Any]:
    """Get current queue status."""
    queue = load_queue()
    return {
        'pending': len(queue['domains']),
        'completed': len(queue['completed']),
        'failed': len(queue['failed']),
        'total': len(queue['domains']) + len(queue['completed']) + len(queue['failed']),
        'pending_list': queue['domains'],
        'completed_list': queue['completed'],
        'failed_list': queue['failed']
    }


def add_domains_to_queue(new_domains: List[str]) -> bool:
    """Add discovered subdomains to the queue (avoid duplicates)."""
    queue = load_queue()
    
    # Normalize and deduplicate
    normalized = [d.strip().lower() for d in new_domains if d.strip()]
    
    # Get existing domains (pending + completed + failed)
    existing = set(queue['domains'])
    existing.update(queue['completed'])
    existing.update([f['domain'] if isinstance(f, dict) else f for f in queue['failed']])
    
    # Add only new domains
    added = [d for d in normalized if d not in existing]
    
    if added:
        queue['domains'].extend(added)
        # Remove duplicates from domains list
        queue['domains'] = list(set(queue['domains']))
        queue['domains'].sort()
        
        if save_queue(queue):
            msg = f"✓ Added {len(added)} subdomain(s) to queue: {', '.join(added[:5])}"
            if len(added) > 5:
                msg += f" ... and {len(added)-5} more"
            print(msg)
            return True
    else:
        print(f"✓ All {len(normalized)} subdomain(s) already in queue or completed")
        return True
    
    return False


def clear_queue() -> bool:
    """Clear the entire queue."""
    return save_queue({'domains': [], 'completed': [], 'failed': []})


def interactive_input_domains() -> bool:
    """Interactively ask user for domains."""
    print("\n" + "=" * 70)
    print("🔒 DOMAIN SECURITY AUDIT - Interactive Domain Input")
    print("=" * 70)
    
    domains = []
    print("\nEnter domain(s) to scan (one per line):")
    print("- Single domain: google.com")
    print("- Multiple: Enter one, press Enter, repeat")
    print("- Type 'done' when finished\n")
    
    while True:
        domain = input(f"Domain {len(domains) + 1} (or 'done'): ").strip().lower()
        
        if domain.lower() == 'done':
            break
        
        if not domain:
            print("⚠️  Empty input, please enter a valid domain")
            continue
        
        if domain in domains:
            print("⚠️  Domain already in list")
            continue
        
        domains.append(domain)
        print(f"✓ Added: {domain}")
    
    if not domains:
        print("\n❌ No domains provided")
        return False
    
    return initialize_queue(domains)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'init':
            # Initialize with domains from arguments
            domains = sys.argv[2:] if len(sys.argv) > 2 else []
            if domains:
                initialize_queue(domains)
            else:
                print("❌ No domains provided")
                sys.exit(1)
        
        elif command == 'status':
            status = get_queue_status()
            print("\n" + "=" * 50)
            print("📊 QUEUE STATUS")
            print("=" * 50)
            print(f"Pending:  {status['pending']}")
            print(f"Completed: {status['completed']}")
            print(f"Failed:   {status['failed']}")
            print(f"Total:    {status['total']}")
            if status['pending_list']:
                print(f"\nPending domains: {', '.join(status['pending_list'])}")
            if status['completed_list']:
                print(f"Completed domains: {', '.join(status['completed_list'])}")
            if status['failed_list']:
                print(f"Failed domains: {[f['domain'] for f in status['failed_list']]}")
        
        elif command == 'clear':
            if clear_queue():
                print("✓ Queue cleared")
            else:
                print("❌ Failed to clear queue")
        
        elif command == 'next':
            next_domain = get_next_domain()
            if next_domain:
                print(next_domain)
            else:
                print("")
        
        elif command == 'complete':
            if len(sys.argv) > 2:
                domain = sys.argv[2]
                if complete_domain(domain):
                    print(f"✓ Marked {domain} as completed")
                    status = get_queue_status()
                    print(f"Remaining: {status['pending']} domains")
                else:
                    print(f"❌ Failed to mark {domain} as completed")
        
        elif command == 'fail':
            if len(sys.argv) > 2:
                domain = sys.argv[2]
                error = sys.argv[3] if len(sys.argv) > 3 else ""
                if fail_domain(domain, error):
                    print(f"✓ Marked {domain} as failed")
                else:
                    print(f"❌ Failed to mark {domain} as failed")
        
        elif command == 'add':
            # Add discovered subdomains: domain_queue_manager.py add sub1.com sub2.com
            if len(sys.argv) > 2:
                new_domains = sys.argv[2:]
                add_domains_to_queue(new_domains)
            else:
                print("❌ No domains provided to add")
    else:
        # Interactive mode
        interactive_input_domains()
