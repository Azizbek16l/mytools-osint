# Multi-arch CLI-only image. GUI is intentionally excluded — PySide6 doubles
# image size and nobody runs a Qt GUI inside a container.
FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml requirements.txt ./
COPY app ./app
COPY cli.py ./
COPY data ./data
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim
RUN useradd -u 1000 -m osint && \
    mkdir -p /home/osint/.local/share/mytools-osint && \
    chown -R osint /home/osint
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER osint
WORKDIR /home/osint
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["osint"]
