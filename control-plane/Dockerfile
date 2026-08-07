# Multi-stage so the runtime image carries no toolchain and no sources.
FROM node:22-slim AS build
WORKDIR /build
COPY verifier/package.json verifier/tsconfig.json ./verifier/
COPY verifier/src ./verifier/src
RUN cd verifier && npm install --omit=dev --no-audit --no-fund \
    && npm install --no-save typescript@^5.7.0 && npx tsc -p tsconfig.json
COPY control-plane/package.json control-plane/tsconfig.json ./control-plane/
COPY control-plane/src ./control-plane/src
RUN cd control-plane && npm install --no-audit --no-fund && npx tsc -p tsconfig.json

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /build/verifier/dist ./verifier/dist
COPY --from=build /build/verifier/package.json ./verifier/
COPY --from=build /build/verifier/node_modules ./verifier/node_modules
COPY --from=build /build/control-plane/dist ./dist
COPY --from=build /build/control-plane/package.json ./
COPY --from=build /build/control-plane/node_modules ./node_modules
# Not distroless:nonroot. uid 65532 cannot open the root-owned launcher socket on
# Confidential Space, and keeping the two images consistent avoids relearning that.
USER node
EXPOSE 8080
CMD ["node", "dist/server.js"]
