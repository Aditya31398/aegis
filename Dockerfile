# Aegis as a container: for CI systems that are not GitHub Actions, and for
# auditing without installing Python.
#
#   docker run --rm -v "$PWD:/work" ghcr.io/aditya31398/aegis audit --policy policies/base.yaml
#   docker run --rm ghcr.io/aditya31398/aegis mcp --server https://host/mcp --out /tmp/out

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY aegis ./aegis
RUN pip wheel --no-cache-dir --no-deps -w /dist .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="aegis" \
      org.opencontainers.image.description="Constraint enforcement and audit for AI agent tool surfaces" \
      org.opencontainers.image.source="https://github.com/Aditya31398/aegis" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=build /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /dist \
 && useradd --create-home --uid 10001 aegis

# Never run an auditor as root: it parses untrusted manifests and talks to
# untrusted servers.
USER aegis
WORKDIR /work
ENTRYPOINT ["aegis"]
CMD ["--help"]
