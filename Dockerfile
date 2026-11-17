# Render builds this to run the Velo Kinetix back end (the server folder).
# The website itself is served by GitHub Pages, not by this container.
FROM node:22-alpine
WORKDIR /app
COPY server/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server/ ./
ENV NODE_ENV=production PORT=10000
EXPOSE 10000
CMD ["node", "index.js"]
