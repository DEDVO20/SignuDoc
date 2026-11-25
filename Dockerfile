
FROM node:24-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci

COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

RUN npm prune --omit=dev

FROM node:24-bookworm-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=builder --chown=node:node /app /app

RUN mkdir -p /app/.data/storage \
    && chown -R node:node /app/.data

USER node

EXPOSE 3000

CMD ["sh", "-c", "npm run db:migrate && npm run start -- --hostname 0.0.0.0"]
