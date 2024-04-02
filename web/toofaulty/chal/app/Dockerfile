# Use the official Node.js image as a parent image
FROM node:16

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install any dependencies
RUN npm install

# Copy the rest of your application's code into the container
COPY . .

# Make start.sh executable
RUN chmod +x start.sh

# Expose the port the app runs on
EXPOSE 8002

# Start the app by running start.sh
CMD ["./start.sh"]
