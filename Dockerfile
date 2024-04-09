FROM php:8.3-cli-alpine3.18

LABEL maintainer="Damian972"
LABEL package="infisical-env-sync"
LABEL version="1.0"

ENV INFISICAL_TOKEN=""
ENV REST_GITHUB_TOKEN=""

# Install Infisical CLI
RUN apk add --no-cache bash curl && curl -1sLf \
'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | bash \
&& apk add infisical

WORKDIR /app

COPY update_secrets.php /app

ENTRYPOINT [ "php", "update_secrets.php" ]