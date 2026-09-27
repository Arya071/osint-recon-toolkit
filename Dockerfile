FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY osint_recon_toolkit/ ./osint_recon_toolkit/
RUN pip install --no-cache-dir .

WORKDIR /data
ENTRYPOINT ["osint-recon"]
CMD ["--help"]
