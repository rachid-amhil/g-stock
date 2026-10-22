# Deployment on the company server

The Docker deployment is for a Linux server with Docker Engine and Docker Compose. The container binds to the internal Docker network; the host publishes it only on `127.0.0.1:8787`. Put the company's HTTPS reverse proxy (IIS, Nginx, Apache, or equivalent) in front of that local port. Do not expose port 8787 directly to the internet or office LAN without TLS.

## Server setup

1. Ask IT for a Linux host, a DNS name such as `stock.company.example`, an HTTPS certificate/reverse-proxy route to `127.0.0.1:8787`, and a regular backup location for the Docker volume `stock-data`.
2. Copy the application source to a private company Git repository or transfer the source bundle to the server. `.dockerignore` excludes the local SQLite database, stock seed file, and built HTML that contains stock seed data.
3. On the company server, copy `.env.example` to `.env`. Enter a unique bootstrap Super Admin password, the Resend key, a sender address from a domain verified with Resend, and the final HTTPS app URL. Do not commit or email `.env`.
4. Build and start from the project directory with `docker compose up -d --build`. The app's private backend listens on `127.0.0.1:8787` on the server for the HTTPS proxy. Persistent records live in Docker volume `stock-data`.
5. Visit the HTTPS address, log in with the bootstrap email/password, then remove `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` from `.env` and restart the service. The app reads bootstrap credentials only when the database has no users.
6. Export a JSON backup from the current local app. After the hosted Super Admin logs in, choose **Importer fichier** to bring the stock collections into the company database. This uploads the backup over HTTPS to the company's server.
7. Ask IT to schedule backups of the `stock-data` volume and test restoring one. Keep the activation email configuration on the company server; the API key is never stored in the browser.

## Reverse proxy expectations

Forward HTTPS requests to `http://127.0.0.1:8787`, preserve the original `Host`, and set/overwrite `X-Forwarded-Proto: https`. The backend uses this proxy header to set the `Secure` cookie flag. Configure the proxy to reject direct public access to the backend port.

This setup is intended for one application instance using one SQLite file. Do not run multiple app containers against the same SQLite database volume.
