FROM sourcepole/qwc-uwsgi-base:alpine-v2023.10.26

ADD requirements.txt /srv/qwc_service/requirements.txt

# Required for pycryptodomex and cffi
RUN \
  apk add --no-cache --update --virtual build-deps gcc python3-dev musl-dev libffi-dev && \
  pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt && \
  apk del build-deps

ADD src /srv/qwc_service/

# Debugging
RUN chown -R $SERVICE_UID:$SERVICE_GID /srv/qwc_service /usr/lib/python3.11/site-packages/authlib
