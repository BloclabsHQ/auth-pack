FROM python:3.12-slim
WORKDIR /auth-pack
RUN pip install --no-cache-dir uv
COPY . .
RUN uv sync
CMD ["uv", "run", "pytest", "-v"]
