# Fixture for output-regression tests. Deliberately vulnerable:
# unpinned base image (:latest) + no non-root USER. Caught natively by
# textscan's IaC rules in --fast mode (no Python / Docker / network).
FROM golang:latest

WORKDIR /app
COPY . .
RUN go build -o /app/server ./...

EXPOSE 8080
CMD ["/app/server"]
