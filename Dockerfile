ARG PYTHON_VERSION=3.13-slim-bookworm
# ---------------------------------- Builder --------------------------------- #
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONUNBUFFERED=1
ENV POETRY_NO_INTERACTION=1
ENV POETRY_VIRTUALENVS_CREATE=0
ENV POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock ./
COPY tcs_garr ./tcs_garr

# Build tcs-garr
RUN <<EOF
pip install --upgrade pip
pip install poetry==2.1.1
touch README.md
poetry install --without dev --no-root
poetry build
EOF
# ---------------------------------------------------------------------------- #

FROM python:${PYTHON_VERSION} AS tcs-garr

ENV PYTHONUNBUFFERED=1
ENV TZ=Europe/Rome

# Add tcs user
RUN <<EOF
groupadd --gid 1000 tcs
useradd --uid 1000 --gid tcs --shell /bin/bash --system tcs
EOF

WORKDIR /app
COPY --from=builder /app/dist/*.whl ./

# Install tcs-garr package
RUN pip install --no-cache-dir ./*.whl && rm ./*.whl

USER tcs

ENTRYPOINT ["tcs-garr"]
