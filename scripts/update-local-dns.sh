#!/bin/bash

# Automated local DNS management for tenant domains
# This script watches for new ingresses and automatically updates /etc/hosts

MINIKUBE_IP=$(minikube ip)
HOSTS_FILE="/etc/hosts"
BACKUP_FILE="/etc/hosts.backup.$(date +%Y%m%d)"

# Create backup
sudo cp "$HOSTS_FILE" "$BACKUP_FILE"

# Function to add domain to hosts
add_domain() {
    local domain="$1"
    local ip="$2"

    if ! grep -q "$domain" "$HOSTS_FILE"; then
        echo "Adding $domain to $HOSTS_FILE"
        echo "$ip $domain" | sudo tee -a "$HOSTS_FILE" > /dev/null
    else
        echo "$domain already exists in $HOSTS_FILE"
    fi
}

# Function to remove domain from hosts
remove_domain() {
    local domain="$1"

    if grep -q "$domain" "$HOSTS_FILE"; then
        echo "Removing $domain from $HOSTS_FILE"
        sudo sed -i.bak "/$domain/d" "$HOSTS_FILE"
    fi
}

# Function to sync ingresses with /etc/hosts
sync_ingresses() {
    echo "Syncing ingresses with /etc/hosts..."

    # Get all ingress hostnames for local.suranku domain
    kubectl get ingress -A -o jsonpath='{range .items[*]}{range .spec.rules[*]}{.host}{"\n"}{end}{end}' | \
    grep "local\.suranku" | \
    while read -r hostname; do
        if [ -n "$hostname" ]; then
            add_domain "$hostname" "$MINIKUBE_IP"
        fi
    done
}

# Function to watch for ingress changes
watch_ingresses() {
    echo "Watching for ingress changes..."
    kubectl get ingress -A -w --no-headers | while read -r line; do
        if echo "$line" | grep -q "local\.suranku"; then
            echo "Detected ingress change: $line"
            sync_ingresses
        fi
    done
}

case "$1" in
    "sync")
        sync_ingresses
        ;;
    "watch")
        sync_ingresses
        watch_ingresses
        ;;
    "add")
        if [ -z "$2" ]; then
            echo "Usage: $0 add <domain>"
            exit 1
        fi
        add_domain "$2" "$MINIKUBE_IP"
        ;;
    "remove")
        if [ -z "$2" ]; then
            echo "Usage: $0 remove <domain>"
            exit 1
        fi
        remove_domain "$2"
        ;;
    *)
        echo "Usage: $0 {sync|watch|add <domain>|remove <domain>}"
        echo ""
        echo "Commands:"
        echo "  sync   - Sync all existing ingresses to /etc/hosts"
        echo "  watch  - Watch for new ingresses and auto-update /etc/hosts"
        echo "  add    - Add a specific domain to /etc/hosts"
        echo "  remove - Remove a specific domain from /etc/hosts"
        exit 1
        ;;
esac