FROM cloudron/base:6.0.0@sha256:9bed4c8fa880645f8e669041ee28febe941481d00e9445e3e5a5483cb541d09b

ARG POSTGRESQL_VERSION=18.6-0ubuntu0.26.04.1

RUN mkdir -p /app/code
WORKDIR /app/code

# clusters are created by start.sh in the persistent dir, not by the package postinst
RUN mkdir -p /etc/postgresql-common/createcluster.d && \
    echo "create_main_cluster = false" > /etc/postgresql-common/createcluster.d/no-main-cluster.conf && \
    apt-get update && \
    apt-get install -y postgresql-18=${POSTGRESQL_VERSION} && \
    rm -rf /var/cache/apt /var/lib/apt/lists

RUN rm /etc/nginx/sites-enabled/* && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log
COPY nginx/readonlyrootfs.conf /etc/nginx/conf.d/readonlyrootfs.conf
COPY nginx/app.conf /etc/nginx/sites-enabled/app.conf

COPY supervisor/* /etc/supervisor/conf.d/
RUN ln -sf /run/supervisord.log /var/log/supervisor/supervisord.log

COPY start.sh backup.sh restore.sh pgtenant.sh common.sh /app/pkg/
COPY www /app/code/www

CMD [ "/app/pkg/start.sh" ]
