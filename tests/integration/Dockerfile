FROM oven/bun:1.4.2-alpine AS bun
FROM python:3.12-alpine
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY server.py /fixture/server.py
ARG FIXTURE_MODE=app
ENV FIXTURE_MODE=${FIXTURE_MODE}
ENTRYPOINT ["/bin/sh", "-c", "exec python3 /fixture/server.py \"$FIXTURE_MODE\""]
