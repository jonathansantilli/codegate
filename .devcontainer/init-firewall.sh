#!/bin/bash
# Firewall rules for CodeGate research container.
# Default-deny outbound policy with allowlist for essential services.

set -euo pipefail

# Only run if iptables is available (requires --cap-add=NET_ADMIN)
if ! command -v iptables &>/dev/null; then
  echo "[firewall] iptables not available — skipping firewall setup"
  exit 0
fi

echo "[firewall] Setting up default-deny outbound policy..."

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS (required for domain resolution)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow HTTPS (443) to essential services only
# GitHub (for cloning repos)
for domain in github.com api.github.com raw.githubusercontent.com objects.githubusercontent.com; do
  for ip in $(dig +short "$domain" 2>/dev/null || true); do
    iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT 2>/dev/null || true
  done
done

# npm registry (for npm ci)
for domain in registry.npmjs.org; do
  for ip in $(dig +short "$domain" 2>/dev/null || true); do
    iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT 2>/dev/null || true
  done
done

# Claude API (for deep scan agent)
for domain in api.anthropic.com claude.ai; do
  for ip in $(dig +short "$domain" 2>/dev/null || true); do
    iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT 2>/dev/null || true
  done
done

# VS Code devcontainer communication (local)
iptables -A OUTPUT -p tcp -d 172.16.0.0/12 -j ACCEPT
iptables -A OUTPUT -p tcp -d 192.168.0.0/16 -j ACCEPT

# Default deny all other outbound
iptables -A OUTPUT -j DROP

echo "[firewall] Outbound policy active. Allowed: GitHub, npm, Claude API, local."
echo "[firewall] All other outbound traffic is blocked."
