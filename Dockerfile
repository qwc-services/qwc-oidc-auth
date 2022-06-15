# WSGI service environment
FROM sourcepole/qwc-uwsgi-base:ubuntu-latest

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y libxmlsec1-dev pkg-config

RUN locale-gen $LANG

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt
