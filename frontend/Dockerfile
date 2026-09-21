# ==============================================================================
# POSEIDON CTI Platform — Hardened Multi-Stage Frontend Dockerfile
# Conforming to Prompt 03 DevSecOps & Principle of Least Privilege
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Production Assets
# ------------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies with lockfile guarantee
COPY package*.json ./
RUN npm ci

# Copy sources and compile production bundle
COPY . .
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Lightweight Hardened Nginx Runtime
# ------------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy compiled SPA bundle
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
