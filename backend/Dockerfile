# Use official Node.js LTS image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY . .

# Expose the application port
EXPOSE 5000

# Set Node environment to development by default
ENV NODE_ENV=development

# Start the application
CMD ["npm", "run", "dev"]
