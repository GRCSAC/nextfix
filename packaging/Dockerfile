# syntax=docker/dockerfile:1
# NextFix server image. Build from the repository root:
#   docker build -t nextfix -f packaging/Dockerfile .
# Run (the /data volume holds the database and caches; see docs/INSTALL.md):
#   docker run -d --name nextfix -p 8790:8790 -v nextfix-data:/data nextfix
# The image carries syft so `--image` scans work when the Docker socket is mounted.

ARG NODE_IMAGE=node:24-alpine
ARG ALPINE_IMAGE=alpine:3.24

# ---- build: dependencies, the dashboard, the esbuild bundle ----
FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/engine/package.json packages/engine/
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && node packaging/build-sea.mjs --bundle-only

# ---- syft: the pinned release for this architecture, checksum verified ----
FROM ${ALPINE_IMAGE} AS syft
ARG TARGETARCH
ARG SYFT_VERSION=1.52.0
ARG SYFT_SHA256_AMD64=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d
ARG SYFT_SHA256_ARM64=c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706
RUN apk add --no-cache curl \
 && case "${TARGETARCH}" in \
      amd64) SUM="${SYFT_SHA256_AMD64}" ;; \
      arm64) SUM="${SYFT_SHA256_ARM64}" ;; \
      *) echo "no syft release for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "${SUM}  /tmp/syft.tgz" | sha256sum -c - \
 && tar -xzf /tmp/syft.tgz -C /usr/local/bin syft \
 && /usr/local/bin/syft version

# ---- runtime: a plain Alpine with the Node binary, the bundle and its assets, and syft ----
# node:24-alpine also carries npm, corepack and yarn, which the server never uses; taking just
# the binary keeps about 60 MB out of the image. ALPINE_IMAGE must match the Alpine release
# the Node image was built on (its /etc/alpine-release) so the musl and libstdc++ match.
FROM ${ALPINE_IMAGE}
ENV NODE_ENV=production     NEXTFIX_HOME=/data
RUN apk add --no-cache libstdc++ libgcc  && addgroup -g 1000 node && adduser -u 1000 -G node -s /bin/sh -D node  && mkdir -p /data && chown node:node /data
COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=syft /usr/local/bin/syft /usr/local/bin/syft
COPY --from=build /src/dist-bundle /app
COPY --chmod=755 packaging/docker-entrypoint.sh /usr/local/bin/nextfix
USER node
WORKDIR /data
VOLUME /data
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3   CMD wget -qO- "http://127.0.0.1:${NEXTFIX_PORT:-8790}/api/health" >/dev/null || exit 1
ENTRYPOINT ["nextfix"]
CMD ["serve"]
