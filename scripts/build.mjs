import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const templatePath = resolve(root, 'work/app.html');
const seedPath = resolve(root, 'work/seed.json');
const outputPath = resolve(root, 'outputs/Gestion de stock.html');
const indexPath = resolve(root, 'outputs/index.html');
const template = readFileSync(templatePath, 'utf8');
const includeSeed = process.env.SEED_MODE !== 'empty' && process.env.NETLIFY !== 'true';
const seed = includeSeed && existsSync(seedPath)
  ? JSON.parse(readFileSync(seedPath, 'utf8'))
  : { inventory: [], movements: [], loans: [], office: [] };
if ((template.match(/__SEED__/g) || []).length !== 1) throw new Error('Expected exactly one __SEED__ placeholder');
const safeSeed = JSON.stringify(seed).replaceAll('<', '\\u003c');
mkdirSync(resolve(root, 'outputs'), { recursive: true });
writeFileSync(outputPath, template.replace('__SEED__', safeSeed));
if (process.env.NETLIFY === 'true') writeFileSync(indexPath, template.replace('__SEED__', safeSeed));
console.log(`Built ${outputPath} (${includeSeed ? seed.inventory?.length || 0 : 0} stock rows${includeSeed ? '' : ', private seed excluded'})`);
