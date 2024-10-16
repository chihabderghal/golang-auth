# Use the Go image based on Alpine Linux
FROM golang:alpine3.20 AS builder

# Set working directory to /app
WORKDIR /app

# Install Air for live reloading
RUN go install github.com/air-verse/air@latest

# Copy module files
COPY go.mod ./
COPY go.sum ./

# Download and verify Go dependencies
RUN go mod download && go mod verify

# Create a volume for the app to enable live file changes
VOLUME ["/app"]

# Expose port 5000
EXPOSE 5000