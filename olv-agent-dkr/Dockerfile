FROM node:20-alpine

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    iproute2 \
    iproute2-tc \
    conntrack-tools \
    openssl \
    bash \
    curl

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev

COPY src/ ./src/

RUN mkdir -p /etc/wireguard /app/certs

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "src/index.js"]
