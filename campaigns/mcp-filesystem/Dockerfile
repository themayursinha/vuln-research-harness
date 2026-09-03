# Node runtime for compiling and probing the pinned filesystem MCP snapshot.
# Target source stays on the read-only snapshot mount, not in this image.
FROM docker.io/library/node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
WORKDIR /app
COPY source/package.json source/package-lock.json /app/
# ignore-scripts: upstream prepare runs tsc/shx against the monorepo layout.
# npm ci uses the committed lockfile so caret ranges cannot float on rebuild.
RUN npm ci --ignore-scripts --include=dev
ENV NODE_PATH=/app/node_modules
