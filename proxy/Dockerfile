FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
# config + logs are mounted by docker-compose
CMD ["node", "src/server.js"]
