import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Export only the stock collections approved for migration. User accounts,
// password hashes, invitations, and sessions are intentionally excluded.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dbPath = process.env.DB_PATH || resolve(root, 'data/gestion-stock.sqlite');
const outputPath = process.env.MIGRATION_EXPORT_PATH || resolve(root, 'data/supabase-migration.json');
const db = new DatabaseSync(dbPath, { readOnly: true });
try {
  const collections = {};
  for (const key of ['inventory', 'movements', 'loans', 'office']) {
    const row = db.prepare('SELECT value FROM app_state WHERE key=?').get(key);
    let value = row ? JSON.parse(row.value) : [];
    if (!Array.isArray(value)) throw new Error(`Invalid ${key} data in SQLite`);
    collections[key] = value;
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(collections, null, 2), { flag: 'wx' });
  console.log(`Exported private migration file: ${outputPath}`);
  console.log(Object.entries(collections).map(([name, rows]) => `${name}: ${rows.length}`).join('\n'));
  console.log('Account credentials and sessions were not exported.');
} finally {
  db.close();
}
