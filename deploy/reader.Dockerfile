# doorman-reader on its own: one Python file and httpx, nothing of Doorman. It reads strangers' mail,
# so its image holds as little as possible: no doorman code, no credentials but its reader key and the
# model API key, no shell tools beyond the slim base.
FROM python:3.13-slim
COPY deploy/reader.lock /tmp/reader.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/reader.lock && rm /tmp/reader.lock \
    && useradd --uid 10002 --no-create-home reader
COPY doorman/reader.py /app/reader.py
USER reader
CMD ["python", "-I", "/app/reader.py"]
