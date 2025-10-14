FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --production
COPY server.js ./server.js
COPY public ./public
EXPOSE 8080
CMD ["node", "server.js"]
