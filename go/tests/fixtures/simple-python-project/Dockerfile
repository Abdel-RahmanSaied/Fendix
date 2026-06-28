# Fixture for output-regression tests. Deliberately vulnerable:
# unpinned base image (:latest) + no non-root USER. Caught natively by
# textscan's IaC rules in --fast mode (no Python / Docker / network).
FROM python:latest

WORKDIR /app
COPY . .

EXPOSE 8000
CMD ["python", "app.py"]
