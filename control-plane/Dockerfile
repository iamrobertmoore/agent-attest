# The control plane depends on the verifier by path (`file:../verifier`) rather than by
# a published version, so that there is exactly one copy of the verification code in the
# system. npm implements that as a RELATIVE symlink inside node_modules, which means the
# directory depth of the runtime image has to match the build image exactly. Flatten it
# and the symlink resolves to a path that does not exist, and the container dies at
# import time with a module-not-found that names a package you can see on disk.
#
# Hence /app/verifier and /app/control-plane in both stages, deliberately.

FROM node:22-slim AS build
WORKDIR /app

COPY verifier/package.json verifier/tsconfig.json ./verifier/
COPY verifier/src ./verifier/src
RUN cd verifier \
 && npm install --no-audit --no-fund \
 && npx tsc -p tsconfig.json \
 && npm prune --omit=dev

COPY control-plane/package.json control-plane/tsconfig.json ./control-plane/
COPY control-plane/src ./control-plane/src
RUN cd control-plane \
 && npm install --no-audit --no-fund \
 && npx tsc -p tsconfig.json \
 && npm prune --omit=dev

FROM node:22-slim
ENV NODE_ENV=production
COPY --from=build --chown=node:node /app/verifier /app/verifier
COPY --from=build --chown=node:node /app/control-plane /app/control-plane
WORKDIR /app/control-plane
USER node
EXPOSE 8080
CMD ["node", "dist/server.js"]
