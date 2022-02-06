FROM node:16-alpine

RUN apk add openssl dumb-init && \
    mkdir /opt/mock-osquery-tls

WORKDIR /opt/mock-osquery-tls

COPY --chown=node package.json package-lock.json sample.conf index.js /opt/mock-osquery-tls/

RUN npm install && \
    chown -R node /opt/mock-osquery-tls

ENV NODE_ENV production

USER node

EXPOSE 8443

ENTRYPOINT ["dumb-init", "node", "index.js"]
