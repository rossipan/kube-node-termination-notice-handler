FROM python:2.7.15-stretch

ENV HOME=/handler
WORKDIR /handler

COPY src/ /
RUN apt-get update && \
    apt-get -y install vim ca-certificates && \
    pip --no-cache-dir --disable-pip-version-check --quiet install -r /res/requirements.txt

CMD ["/usr/local/bin/python", "/handler/main.py"]