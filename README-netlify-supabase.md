# Netlify + Supabase deployment

The hosted application serves its static UI from Netlify and runs its API as Netlify Functions. The API talks to the private Supabase tables with a server-only service role key; the browser never receives that key. The local SQLite database remains unchanged as a backup.

## 1. Apply the database schema

Sign in to the Supabase account that owns project `vupsoycszxznkfzmaray`, open its SQL Editor, and run the full file `supabase/migrations/20261022000100_initial_schema.sql` once. The database tables and atomic write functions are private to the API.

## 2. Set Netlify environment variables

For the Netlify site, add these variables in **Site configuration → Environment variables**. Do not put secrets in source files, Git, or the browser.

- `SUPABASE_URL` = `https://vupsoycszxznkfzmaray.supabase.co`
- `SUPABASE_SECRET_KEY` = the project's **server-only** secret key (`sb_secret_…`)
- `BOOTSTRAP_ADMIN_EMAIL` = the email for the first Super Admin
- `BOOTSTRAP_ADMIN_PASSWORD` = a new password of at least 12 characters
- `BOOTSTRAP_ADMIN_NAME` = the first Super Admin's display name (optional)

For invitation emails, also set `RESEND_API_KEY` and `INVITATION_FROM` using a verified sender. Netlify provides the deployed site URL as `URL`, which is used for invitation links.

The first API request creates the bootstrap account only when the `users` table is empty. Once it exists, remove the two bootstrap variables from Netlify and redeploy.

## 3. Deploy the app

Deploy the project directory to the selected Netlify site with `netlify deploy --prod`. `netlify.toml` builds the UI without private seed data, publishes `outputs/index.html`, and routes `/api/*` to the API function. Do not upload the `data/` folder or the local SQLite database.

## 4. Import the approved stock data

After deployment and first Super Admin login, choose **Importer fichier** and select the local private file `data/supabase-migration.json`. It contains inventory, stock movements (including client phone numbers), loans, and office stock only. It excludes user accounts, password hashes, invitations, and sessions. Keep the SQLite file and the migration JSON as local backup copies until the hosted data is confirmed.

## Local preparation

The export file was made from the local SQLite database with:

```powershell
node scripts/export-supabase-migration.mjs
```

The output is ignored by Git and must not be committed.
