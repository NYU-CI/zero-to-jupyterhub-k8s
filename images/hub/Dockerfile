FROM ubuntu:18.04

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  git \
  python3 \
  python3-dev \
  python3-pip \
  python3-setuptools \
  libcurl4-openssl-dev \
  libssl-dev \
  build-essential \
  && \
  apt-get purge && apt-get clean

ARG NB_USER=adrf
ARG NB_UID=1000
ARG HOME=/home/adrf

ENV LANG C.UTF-8

RUN adduser --disabled-password \
  --gecos "Default user" \
  --uid ${NB_UID} \
  --home ${HOME} \
  --force-badname \
  ${NB_USER}

ARG JUPYTERHUB_VERSION=0.9.*

WORKDIR /tmp
ADD adrf adrf
ADD requirements.txt requirements.txt
RUN pip3 install --no-cache-dir \
  jupyterhub==${JUPYTERHUB_VERSION} \
  -r requirements.txt

WORKDIR /
ADD jupyterhub_config.py /srv/jupyterhub_config.py

ADD z2jh.py /usr/local/lib/python3.6/dist-packages/z2jh.py
ADD cull_idle_servers.py /usr/local/bin/cull_idle_servers.py

WORKDIR /srv/jupyterhub

# So we can actually write a db file here
RUN chown ${NB_USER}:${NB_USER} /srv/jupyterhub

# JupyterHub API port
EXPOSE 8081

#USER ${NB_USER}
CMD ["jupyterhub", "--config", "/srv/jupyterhub_config.py"]
