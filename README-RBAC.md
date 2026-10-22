# RBAC backend for Gestion de stock

## Current app architecture

The original project was a standalone HTML application with browser `localStorage`; it had no server, authentication, or database. The application is now served through a Node.js 24 backend using the built-in SQLite driver, so it needs no third-party runtime packages. The stock page requires a server login, loads shared stock data from the API, and sends edits through permission-checked endpoints. User and role administration also uses the server APIs.

## Start locally

Install Node.js 24 or newer. In PowerShell, set a one-time bootstrap account and start the server:

```powershell
$env:BOOTSTRAP_ADMIN_EMAIL = 'admin@example.com'
$env:BOOTSTRAP_ADMIN_PASSWORD = 'replace-with-a-long-unique-password'
$env:BOOTSTRAP_ADMIN_NAME = 'Super Admin'
node backend/server.mjs
Remove-Item Env:BOOTSTRAP_ADMIN_EMAIL, Env:BOOTSTRAP_ADMIN_PASSWORD, Env:BOOTSTRAP_ADMIN_NAME
```

Open `http://127.0.0.1:8787`. The bootstrap variables are only read when the database has no users. Use a password of at least 12 characters. Keep the SQLite file private; by default it is `data/gestion-stock.sqlite`. Set `DB_PATH` to move it and `PORT` to change the port. The server binds to `127.0.0.1` by default. For several computers, host it on a trusted server, put HTTPS in front of it, and set `HOST=0.0.0.0` only behind a firewall and TLS reverse proxy. Do not expose the plain HTTP listener to the internet.

After editing the HTML template or stock seed, run `npm run build` to regenerate `outputs/Gestion de stock.html`; this inserts the JSON seed into the served page.

The database migrations and default role/permission records are created on first start. Passwords are stored as per-user salted scrypt hashes. Session identifiers are random, stored hashed in SQLite, and delivered in HttpOnly, SameSite=Strict cookies. User invitations use the Resend email API. New users are inactive until they follow their one-time, 48-hour activation link and choose a password of at least 12 characters.

### Configure invitation email

Create a Resend API key and verify the sender address/domain in Resend. Keep the key on the server only. Set these variables in the PowerShell window that runs the app, then restart the server:

```powershell
$env:RESEND_API_KEY = 're_...'
$env:INVITATION_FROM = 'Gestion de stock <stock@example.com>'
$env:PUBLIC_APP_URL = 'https://stock.example.com'
node backend/server.mjs
```

`PUBLIC_APP_URL` must be reachable by the invited person. The app currently runs at `http://localhost:8787` for local use; an emailed `localhost` activation link only works on the same computer. For colleagues, host the app on an office server behind HTTPS and set `PUBLIC_APP_URL` to that HTTPS address. Do not commit the API key or paste it into the browser app. If email configuration is missing or Resend rejects a message, the invitation is not left half-created and the form shows the error.

## Deploy to Render

`render.yaml` defines a Node web service, health check, environment variables, and a persistent disk for SQLite. The disk requires a paid Render web-service plan. Before pushing the project to a private Git repository, review `.gitignore`: the local seed workbook data, SQLite database, and built HTML are excluded. Render builds the HTML itself; if `work/seed.json` is absent, the initial hosted database starts empty. To bring the current stock online, first use **Sauvegarder fichier** locally, deploy the service, then use **Importer fichier** in the hosted app. Set `PUBLIC_APP_URL` to the generated HTTPS `onrender.com` address. Render's Blueprint asks for secrets marked `sync: false`; set the invitation email variables if email invitations should work. Set the bootstrap admin email and a new long password for the new hosted database. Review the service and disk cost in Render before confirming deployment.

For deployment on the company's own server instead, see [README-company-server.md](README-company-server.md). It includes a Docker Compose setup with persistent SQLite storage and HTTPS reverse-proxy requirements.

## API overview

- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- `GET /api/state`, `PUT /api/state` (server checks every changed collection against the caller's permissions)
- `GET /api/admin/users`, `POST /api/admin/users`, `PATCH /api/admin/users/:id`, `DELETE /api/admin/users/:id`
- `POST /api/admin/users/:id/password`
- `POST /api/admin/users/:id/invitation` (resend a pending activation link)
- `POST /api/auth/activate` (one-time invitation token and new password)
- `GET /api/admin/roles`, `PUT /api/admin/roles/permissions`
- `POST /api/migration/import` (Super Admin only; imports arrays named `inventory`, `movements`, `loans`, and `office` from the current JSON backup)

Roles are `Super Admin`, `Admin`, `Magasinier`, and `Consultation`. Each role is linked to a set of permissions for `products`, `stock`, `purchases`, `sales`, `suppliers`, `customers`, `reports`, and `users`, each with `view`, `create`, `update`, and `delete`. The stock app currently stores inventory, movements, loans, and office stock; the other permission areas are ready for corresponding modules. The last active Super Admin cannot be disabled, demoted, or deleted. Only a Super Admin can assign the Super Admin role or change role permissions. Stock edits use optimistic revision checks to avoid silently overwriting another user's concurrent changes.

## Migrate current browser data

A browser opened with `file:///` has a separate storage origin from the server. Before switching, use **Sauvegarder fichier** in the old app to export JSON. Then log into the server app as Super Admin and use **Importer fichier** to load that JSON into the shared database. The import replaces the shared stock arrays; keep a copy of the JSON first. If this app was previously served from the same localhost origin, it also offers to import its existing browser data at login. New server databases are initialized from the project's stock seed.

## Tests

Run `node backend/rbac.test.mjs` (or `npm test` with npm installed). Tests cover authentication, password rejection, permitted and denied stock operations, user administration access, and the last-Super-Admin safeguard.
