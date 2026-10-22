FROM node:24-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DB_PATH=/var/lib/gestion-stock/gestion-stock.sqlite

WORKDIR /app
COPY package.json ./
COPY backend ./backend
COPY scripts ./scripts
COPY work/app.html ./work/app.html
RUN mkdir -p /var/lib/gestion-stock \
    && chown -R node:node /var/lib/gestion-stock /app \
    && node scripts/build.mjs

USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "backend/server.mjs"]
