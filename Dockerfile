FROM alpine:latest
MAINTAINER Zach Grace (@ztgrace)

RUN mkdir /changeme
COPY . /changeme/

RUN apk update \
    && apk add --no-cache --virtual .changeme-deps \
        bash \
        libxml2 \
        py-lxml \
        py-pip \
    && apk add --no-cache --virtual .build-deps \
        ca-certificates \
        gcc \
        g++ \
	    libffi-dev \
        libtool \
        libxml2-dev \
        make \
	    musl-dev \
        postgresql-dev \
        python-dev \
        unixodbc-dev \
    && pip install -r /changeme/requirements.txt \
    && apk del .build-deps \
    && find /usr/ -type f -a -name '*.pyc' -o -name '*.pyo' -exec rm '{}' \; \
    && ln -s /changeme/changeme.py /usr/local/bin/

ENV HOME /changeme
ENV PS1 "\033[00;34mchangeme>\033[0m "
WORKDIR /changeme
ENTRYPOINT ["./changeme.py"]
