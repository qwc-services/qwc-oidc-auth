FROM sourcepole/qwc-uwsgi-base:alpine-latest

# Required for pycryptodomex and cffi
RUN apk add --no-cache --update gcc python3-dev musl-dev libffi-dev

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt

# Debugging
RUN chown -R 33:33 /srv/qwc_service /usr/lib/python3.9/site-packages/authlib
