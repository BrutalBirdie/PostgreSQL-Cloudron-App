FROM golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e AS panel

WORKDIR /src
COPY panel/go.mod panel/go.sum ./
RUN go mod download
COPY panel/ ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/panel .

FROM cloudron/base:6.0.1@sha256:7b1e729960c3ca312d26e886917ba89483241bba0219ff292858e10d9d5768ee

# renovate: datasource=deb depName=postgresql-18
ARG POSTGRESQL_VERSION=18.6-0ubuntu0.26.04.1

# links the GHCR package to the repo - https://docs.github.com/en/packages/learn-github-packages/connecting-a-repository-to-a-package
LABEL org.opencontainers.image.source=https://github.com/BrutalBirdie/PostgreSQL-Cloudron-App

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
COPY pam/pgpanel /etc/pam.d/pgpanel
RUN ln -sf /run/supervisord.log /var/log/supervisor/supervisord.log

COPY --from=panel /out/panel /app/code/panel
COPY start.sh backup.sh restore.sh pgtenant.sh common.sh /app/pkg/

CMD [ "/app/pkg/start.sh" ]
