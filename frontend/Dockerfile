# Build stage
# Base images are digest-pinned (security review 2026-07-19, L6) so the build is
# reproducible and a floating-tag repoint / upstream tag compromise can't land in
# the image without a lockstep review — matching the digest-pinned backend
# Dockerfiles. Bump the digest deliberately alongside the tag when updating.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage with nginx (digest-pinned — see the builder stage note)
FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

# Create non-root user for security (nginx user already exists in alpine)
# Configure nginx to run as non-root user
RUN sed -i 's/user  nginx;/user  nginx;/' /etc/nginx/nginx.conf && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Adjust permissions
RUN chown -R nginx:nginx /usr/share/nginx/html

# Switch to non-root user
USER nginx

# Use port 8080 instead of 80 (non-privileged port)
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
