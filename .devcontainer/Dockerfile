FROM node:22-bookworm

# System dependencies for scanning research
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sqlite3 \
    jq \
    curl \
    ca-certificates \
    dnsutils \
    iptables \
    sudo \
    zsh \
    && rm -rf /var/lib/apt/lists/*

# Give the existing node user sudo access
RUN echo "node ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/node \
    && chmod 0440 /etc/sudoers.d/node \
    && chsh -s /bin/zsh node

# Install Claude Code globally
RUN npm install -g @anthropic-ai/claude-code

# Copy firewall initialization script
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN chmod +x /usr/local/bin/init-firewall.sh

# Switch to node user
USER node
WORKDIR /workspace
