FROM python:3.11-slim-bullseye

WORKDIR /app

# uwsgi must be compiled - install necessary build tools, compile uwsgi
# and then remove the build tools to minimize image size
# (buildDeps are removed, deps are kept)
RUN apt-get update  && apt-get -y install cron
RUN apt-get install -y iputils-ping
RUN apt-get install -y net-tools
RUN touch /var/log/cron.log
COPY reqs.txt /app/reqs.txt

RUN set -ex \
    && buildDeps=' \
        build-essential \
        gcc \
    ' \
    && deps=' \
        htop \
    ' \
    && apt-get install -y $buildDeps $deps --no-install-recommends  && rm -rf /var/lib/apt/lists/* \
    && pip install uWSGI==2.0.22 \
    && pip install -r /app/reqs.txt \
    && apt-get purge -y --auto-remove $buildDeps \
    && find /usr/local -depth \
    \( \
        \( -type d -a -name test -o -name tests \) \
        -o \
        \( -type f -a -name '*.pyc' -o -name '*.pyo' \) \
    \) -exec rm -rf '{}' +

# install other py libs - not require compilation

# copy source files
COPY conf /app/conf
COPY py /app/py
#COPY real-server-config.json /app/real-server-config.json
COPY migrations /app/migrations
#COPY migrations_sqlite /app/migrations_sqlite
COPY scripts /app/scripts
COPY templates /app/templates
#COPY test /app/test
COPY conf/loginscript.sh /etc/profile
COPY migratedb.py /app/

# background spooler dir
RUN mkdir /tmp/pysrv_spooler

# we don't need this file with Docker but uwsgi looks for it
RUN echo `date +%s` >/app/VERSION

EXPOSE 80


# our server config file
# - you should write your own config file and put OUTSIDE the repository
#   since the config file contains secrets
# - here I use the sample template from repo
# - it is also possible to override the config with env variables, either here
#   or in Amazon ECS or Kubernetes configuration
#COPY /app/real-server-config.json /app/real-server-config.json
# ENV PYSRV_DATABASE_HOST host.docker.internal
# ENV PYSRV_REDIS_HOST host.docker.internal
# ENV PYSRV_DATABASE_PASSWORD x

# build either a production or dev image

ARG BUILDMODE=production
ENV ENVBUILDMODE=$BUILDMODE

RUN echo "BUILDMODE $ENVBUILDMODE"

# run in shell mode with ENV expansion
#CMD /etc/init.d/cron start  ; uwsgi --ini /app/conf/uwsgi.ini:uwsgi-$ENVBUILDMODE --touch-reload=/app/reload
RUN apt update
RUN apt install -y nano
CMD cron ; uwsgi --ini /app/conf/uwsgi.ini:uwsgi-$ENVBUILDMODE --touch-reload=/app/reload