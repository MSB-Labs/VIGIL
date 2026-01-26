# VIGIL Sandbox Container
# Minimal Node.js environment for package analysis

FROM node:20-alpine

# Install basic tools for analysis
RUN apk add --no-cache \
    bash \
    grep \
    findutils \
    coreutils

# Create non-root user for safety
RUN adduser -D -s /bin/bash vigil

# Set working directory
WORKDIR /home/vigil

# Switch to non-root user
USER vigil

# Set npm to be less verbose and disable update checks
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_FUND=false
ENV NO_UPDATE_NOTIFIER=1

# Default command
CMD ["/bin/bash"]
