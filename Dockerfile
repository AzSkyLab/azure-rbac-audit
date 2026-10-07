# Scheduled collector image (e.g. Azure Container Apps job with a user-assigned managed identity).
# Mount the config at /config/config.yaml; evidence is written to /evidence and published per `publish:`.
FROM python:3.13-slim

RUN useradd --create-home --uid 10001 collector && mkdir /evidence && chown collector /evidence
WORKDIR /app
COPY pyproject.toml README.md ./
COPY rbac_audit ./rbac_audit
RUN pip install --no-cache-dir '.[publish]' && rm -rf /root/.cache

USER collector
WORKDIR /evidence
ENTRYPOINT ["rbac-audit"]
CMD ["collect", "--config", "/config/config.yaml", "--publish", "--json"]
