FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
# "ip" (iproute2) is used for best-effort MAC lookup of LAN players
RUN apk add --no-cache iproute2
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
# config, logs and data are mounted by docker-compose
CMD ["node", "src/server.js"]
