FROM sourcepole/qwc-uwsgi-base:alpine-v2025.10.13

WORKDIR /srv/qwc_service
ADD pyproject.toml uv.lock ./

# Required for pycryptodomex and cffi
RUN \
    apk add --no-cache --update --virtual build-deps gcc python3-dev musl-dev libffi-dev && \
    uv sync --frozen && \
    uv cache clean && \
    apk del build-deps

ADD src /srv/qwc_service/
