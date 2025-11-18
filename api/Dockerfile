FROM golang:1.25.4

# Install air for hot reload
RUN go install github.com/cosmtrek/air@v1.49.0

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

EXPOSE 8080
CMD ["air"]