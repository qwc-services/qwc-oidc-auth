FROM sourcepole/qwc-uwsgi-base:alpine-latest

# Required for pycryptodomex and cffi
RUN apk add --no-cache --update gcc python3-dev musl-dev libffi-dev

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt

# Debugging
RUN chown -R $SERVICE_UID:$SERVICE_GID /srv/qwc_service /usr/lib/python3.11/site-packages/authlib
