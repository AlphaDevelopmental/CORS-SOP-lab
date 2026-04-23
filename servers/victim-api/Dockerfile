FROM node:20-alpine

WORKDIR /app

# Install dependencies first (cached layer)
COPY package*.json ./
RUN npm install

# Copy source (overridden by volume mount in docker-compose)
COPY . .

EXPOSE 3000

CMD ["node", "app.js"]
