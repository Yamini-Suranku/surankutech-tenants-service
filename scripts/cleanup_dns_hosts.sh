#!/bin/bash
"""
DNS Hosts Cleanup Script
Removes SurankuTech development DNS entries from /etc/hosts

This script removes entries like:
- 127.0.0.1 palls2.local.suranku
- 127.0.0.1 tommy.local.suranku
- etc.
"""

set -e

echo "🌐 Cleaning up SurankuTech DNS entries from /etc/hosts..."

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script requires sudo access to modify /etc/hosts"
    echo "💡 Run: sudo $0"
    exit 1
fi

# Backup hosts file
HOSTS_FILE="/etc/hosts"
BACKUP_FILE="/etc/hosts.backup.$(date +%Y%m%d_%H%M%S)"

if [ -f "$HOSTS_FILE" ]; then
    cp "$HOSTS_FILE" "$BACKUP_FILE"
    echo "📋 Backup created: $BACKUP_FILE"
else
    echo "❌ /etc/hosts file not found"
    exit 1
fi

# Count existing entries
EXISTING_COUNT=$(grep -c "local\.suranku" "$HOSTS_FILE" || echo "0")
echo "📊 Found $EXISTING_COUNT SurankuTech DNS entries"

if [ "$EXISTING_COUNT" -eq 0 ]; then
    echo "✅ No SurankuTech DNS entries found - nothing to clean"
    exit 0
fi

# Show what will be removed
echo "🗑️  Will remove these entries:"
grep "local\.suranku" "$HOSTS_FILE" | sed 's/^/  /'

# Ask for confirmation
read -p "❓ Proceed with cleanup? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cleanup cancelled"
    exit 0
fi

# Remove SurankuTech entries
sed -i.tmp '/local\.suranku/d' "$HOSTS_FILE"

# Verify cleanup
NEW_COUNT=$(grep -c "local\.suranku" "$HOSTS_FILE" || echo "0")
REMOVED_COUNT=$((EXISTING_COUNT - NEW_COUNT))

echo "✅ Removed $REMOVED_COUNT DNS entries"
echo "📊 Remaining SurankuTech entries: $NEW_COUNT"

if [ "$NEW_COUNT" -eq 0 ]; then
    echo "🎉 All SurankuTech DNS entries cleaned successfully!"
else
    echo "⚠️  Some entries may remain - check manually:"
    grep "suranku" "$HOSTS_FILE" || echo "  (none found)"
fi

# Clean up temp file
rm -f "$HOSTS_FILE.tmp"

echo "✨ DNS cleanup complete!"
echo "💡 You can now test with fresh organization DNS entries"