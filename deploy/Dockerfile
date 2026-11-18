FROM python:3.13-slim

# libseccomp2: the plugin sandbox (doorman/sandbox.py); the slim image has it already, this keeps it there
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 doorman
WORKDIR /app
# exactly the tested packages, each checked against its hash (deploy/requirements.lock, written by
# deploy/lock.py); then Doorman itself, without resolving anything again
COPY deploy/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock && rm /tmp/requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY doorman ./doorman
RUN pip install --no-cache-dir --no-deps --no-build-isolation .

# No USER line: the container starts as root, and `doorman-admin serve` keeps only a small root process
# (doorman/privsep.py) that runs Doorman as the user doorman and starts each plugin as a Linux user of
# its own (20000+). Every other doorman-admin command, e.g. through `docker compose exec`, drops to doorman.
WORKDIR /data
ENV DOORMAN_CONFIG=/data/doorman.yaml
EXPOSE 8710 8711
CMD ["doorman-admin", "serve"]
