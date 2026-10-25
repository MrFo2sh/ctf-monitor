FROM node:20-alpine
WORKDIR /app
COPY simulate.js ./
ENV TARGET=http://127.0.0.1:8888
CMD ["node", "simulate.js", "--loop"]
