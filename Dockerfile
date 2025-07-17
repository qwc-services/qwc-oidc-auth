FROM sourcepole/qwc-uwsgi-base:alpine-v2025.01.24

WORKDIR /srv/qwc_service
ADD pyproject.toml uv.lock ./

# Required for pycryptodomex and cffi
# postgresql-dev libpq-dev required for psycopg2
RUN \
    apk add --no-cache --update --virtual build-deps gcc python3-dev musl-dev libffi-dev && \
    apk add --no-cache --update --virtual postgresql-dev libpq-dev && \
    uv sync --frozen && \
    uv cache clean && \
    apk del build-deps

ADD src /srv/qwc_service/
