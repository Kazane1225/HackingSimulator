FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json ./
# Run unprivileged; the compose file also drops all capabilities and mounts
# the root filesystem read-only.
USER node
EXPOSE 3000
CMD ["node", "dist/index.js"]
