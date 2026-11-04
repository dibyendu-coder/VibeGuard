# Example Dockerfile with common container misconfigurations
FROM node:latest

WORKDIR /app

# Copies everything including local .env
COPY . .

RUN npm install

EXPOSE 3000

# Runs as root (default user, not specified USER node)
CMD ["node", "app.js"]

