# Worker Lambda image: the scan code plus Semgrep.
#
# Semgrep unpacks to ~290 MB, over the 250 MB limit of a zip-based Lambda, so the worker runs
# from this container image instead (limit 10 GB). The API function stays a small zip.
#
#   docker build --platform linux/arm64 -t vibeaudit-worker backend
#
# Semgrep gets its own virtualenv so its pinned dependencies can't clash with the app's.
FROM public.ecr.aws/lambda/python:3.12

ARG SEMGREP_VERSION=1.185.0

RUN python -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir --disable-pip-version-check "semgrep==${SEMGREP_VERSION}" \
 && /opt/semgrep/bin/semgrep --version

COPY requirements-lambda.txt /tmp/requirements-lambda.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r /tmp/requirements-lambda.txt \
 && rm /tmp/requirements-lambda.txt

COPY app ${LAMBDA_TASK_ROOT}/app
COPY rules ${LAMBDA_TASK_ROOT}/rules

# The worker never phones home: no metrics, no version check, no token (public mode is
# locked to the community engine and VibeAudit's own rules in code as well).
ENV SEMGREP_BIN=/opt/semgrep/bin/semgrep \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

CMD ["app.lambda_handler.worker"]
