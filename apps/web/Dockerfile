FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY apps/web/package*.json ./
COPY packages/db/package.json ./packages/db/
COPY turbo.json ./
COPY package.json ./

# Install dependencies
RUN npm install -g pnpm
RUN pnpm install

# Copy source code
COPY apps/web/ .
COPY packages/ ./packages/

# Generate Prisma client
RUN cd packages/db && pnpm db:generate

# Build application
RUN pnpm build

EXPOSE 3000

CMD ["pnpm", "start"]