FROM oven/bun:1.4.5-alpine@sha256:da816670775f4c2b4e990b6b1847cf5540dcdc721a42033dd331ce7a88ba6a3b AS bun
FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
RUN apk add --no-cache libstdc++
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY server.py /fixture/server.py
ARG FIXTURE_MODE=app
ENV FIXTURE_MODE=${FIXTURE_MODE}
ENTRYPOINT ["/bin/sh", "-c", "exec python3 /fixture/server.py \"$FIXTURE_MODE\""]
