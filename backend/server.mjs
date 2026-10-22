import { createServer } from 'node:http';
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const scrypt = promisify(scryptCallback);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dbPath = process.env.DB_PATH || resolve(root, 'data/gestion-stock.sqlite');
mkdirSync(dirname(dbPath), { recursive: true });
const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '127.0.0.1';
const cookieName = 'stock_session';
const sessionSeconds = 8 * 60 * 60;
export const db = new DatabaseSync(dbPath);
db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');

export const catalog = {
  products: ['view', 'create', 'update', 'delete'], stock: ['view', 'create', 'update', 'delete'],
  purchases: ['view', 'create', 'update', 'delete'], sales: ['view', 'create', 'update', 'delete'],
  suppliers: ['view', 'create', 'update', 'delete'], customers: ['view', 'create', 'update', 'delete'],
  reports: ['view', 'create', 'update', 'delete'], users: ['view', 'create', 'update', 'delete']
};
const roles = ['Super Admin', 'Admin', 'Magasinier', 'Consultation'];
const stateMap = { inventory: ['products', 'stock'], movements: ['sales', 'stock'], loans: ['stock'], office: ['products', 'stock'] };

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, last_login TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS permissions(id INTEGER PRIMARY KEY, section TEXT NOT NULL, action TEXT NOT NULL, UNIQUE(section,action));
CREATE TABLE IF NOT EXISTS user_roles(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY(user_id,role_id));
CREATE TABLE IF NOT EXISTS role_permissions(role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY(role_id,permission_id));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS user_invitations(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_state(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);`);
db.prepare("INSERT OR IGNORE INTO app_meta(key,value) VALUES('state_revision','0')").run();

const preset = (role, section, action) => role === 'Super Admin' ||
  (role === 'Admin' && action !== 'delete') ||
  (role === 'Consultation' && action === 'view') ||
  (role === 'Magasinier' && ((['products','stock'].includes(section) && ['view','create','update'].includes(action)) || (section==='purchases' && action==='view') || (section==='sales' && ['view','create','update'].includes(action))));
for (const role of roles) db.prepare('INSERT OR IGNORE INTO roles(name) VALUES(?)').run(role);
for (const [section, actions] of Object.entries(catalog)) for (const action of actions) db.prepare('INSERT OR IGNORE INTO permissions(section,action) VALUES(?,?)').run(section, action);
const putPreset = db.prepare(`INSERT OR IGNORE INTO role_permissions(role_id,permission_id) SELECT r.id,p.id FROM roles r,permissions p WHERE r.name=? AND p.section=? AND p.action=?`);
for (const role of roles) for (const [section, actions] of Object.entries(catalog)) for (const action of actions) if (preset(role, section, action)) putPreset.run(role, section, action);
if (process.env.RBAC_SKIP_SEED!=='1' && db.prepare('SELECT COUNT(*) n FROM app_state').get().n===0) {
  const seedPath=resolve(root,'work/seed.json');
  if(existsSync(seedPath)){const initial=JSON.parse(readFileSync(seedPath,'utf8'));for(const key of Object.keys(stateMap)){initial[key]=(initial[key]||[]).map((x,i)=>({...x,id:x.id||`initial-${key}-${i}`}));}initial.loans=initial.loans.map(x=>({...x,returnedAt:x.returnedAt||x.returnDate||'',expectedReturn:x.expectedReturn||''}));for(const key of Object.keys(stateMap))db.prepare('INSERT OR IGNORE INTO app_state(key,value) VALUES(?,?)').run(key,JSON.stringify(initial[key]||[]));}
}

function hashToken(token) { return createHash('sha256').update(token).digest('hex'); }
function parseCookies(header = '') { return Object.fromEntries(header.split(';').map(x => x.trim().split('=').map(decodeURIComponent)).filter(x => x.length === 2)); }
function send(res, status, body, extra = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra }); res.end(JSON.stringify(body)); }
function fail(status, message) { const e = new Error(message); e.status = status; throw e; }
async function body(req) { let chunks=[]; for await (const c of req) chunks.push(c); if (Buffer.concat(chunks).length > 2_000_000) fail(413,'Request too large'); try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { fail(400,'Invalid JSON'); } }
function sessionUser(req) { const token = parseCookies(req.headers.cookie)[cookieName]; if (!token) return null; const row = db.prepare('SELECT u.id,u.name,u.email,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hashToken(token), Math.floor(Date.now()/1000)); if (!row || !row.active) return null; return row; }
function permissions(userId) { return db.prepare('SELECT DISTINCT p.section,p.action FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id JOIN users u ON u.id=ur.user_id WHERE u.id=? AND u.active=1').all(userId); }
function has(userId, section, action) { return permissions(userId).some(p => p.section===section && p.action===action); }
function requirePermission(user, section, action) { if (!has(user.id, section, action)) fail(403, `Missing permission: ${section}.${action}`); }
function transaction(fn) { db.exec('BEGIN IMMEDIATE'); try { const result=fn(); db.exec('COMMIT'); return result; } catch(e) { db.exec('ROLLBACK'); throw e; } }
function identity(key,row){if(row&&row.id!==undefined&&row.id!==null)return `id:${row.id}`;if(row&&row.serial)return `serial:${row.serial}`;if(row&&(row.type||row.reference||row.brand))return `item:${row.type||''}|${row.reference||''}|${row.brand||''}`;return `value:${JSON.stringify(row)}`;}
function businessIdentity(row){if(row&&row.serial)return `serial:${row.serial}`;if(row&&(row.type||row.reference||row.brand))return `item:${row.type||''}|${row.reference||''}|${row.brand||''}`;return `value:${JSON.stringify(row)}`;}
function normalizeRows(oldRows,newRows){const available=new Set(oldRows.map((_,i)=>i));return newRows.map(row=>{let index=-1;if(row?.id!==undefined)index=oldRows.findIndex((x,i)=>available.has(i)&&x.id===row.id);if(index<0)index=oldRows.findIndex((x,i)=>available.has(i)&&JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k])=>k!=='id')))===JSON.stringify(Object.fromEntries(Object.entries(row||{}).filter(([k])=>k!=='id'))));if(index<0)index=oldRows.findIndex((x,i)=>available.has(i)&&businessIdentity(x)===businessIdentity(row));if(index>=0){available.delete(index);return {...row,id:row.id??oldRows[index].id??randomUUID()}}return {...row,id:row?.id??randomUUID()}})}
function changedActions(key,oldRows,newRows){const pending=new Map();for(const row of oldRows){const k=identity(key,row);if(!pending.has(k))pending.set(k,[]);pending.get(k).push(row)}const actions=new Set();for(const row of newRows){const k=identity(key,row),group=pending.get(k);if(!group?.length){actions.add('create');continue}const old=group.shift();if(JSON.stringify(old)!==JSON.stringify(row))actions.add('update')}for(const group of pending.values())if(group.length)actions.add('delete');return actions;}
function activeSuperAdmins() { return db.prepare(`SELECT COUNT(DISTINCT u.id) n FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id WHERE u.active=1 AND r.name='Super Admin'`).get().n; }
function userRecord(id) { return db.prepare('SELECT id,name,email,active,last_login AS lastLogin,created_at AS createdAt FROM users WHERE id=?').get(id); }
function userRoles(id) { return db.prepare('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=? ORDER BY r.id').all(id).map(x=>x.name); }
function safeUser(id) { const u=userRecord(id); return u ? {...u,roles:userRoles(id)} : null; }
function requireAuth(req) { const user=sessionUser(req); if (!user) fail(401,'Authentication required'); return user; }
function ensureSameOrigin(req) { const origin=req.headers.origin; if (!origin) return; const expected=`http://${req.headers.host}`; const expectedTls=`https://${req.headers.host}`; if (origin!==expected && origin!==expectedTls) fail(403,'Cross-origin request rejected'); }
function sessionCookie(req,token,maxAge=sessionSeconds){const secure=req.socket.encrypted||req.headers['x-forwarded-proto']==='https'?' Secure;':'';return `${cookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge};${secure}`;}
async function verifyPassword(password, salt, expected) { const actual=await scrypt(password,salt,64); return timingSafeEqual(actual,Buffer.from(expected,'hex')); }
async function passwordFields(password) { const salt=randomBytes(16).toString('hex'); const passwordHash=(await scrypt(password,salt,64)).toString('hex'); return {salt,passwordHash}; }
function escapeHtml(value) { return String(value).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c])); }
async function sendInvitationEmail({email,name,token}) {
  const apiKey=process.env.RESEND_API_KEY, from=process.env.INVITATION_FROM, appUrl=process.env.PUBLIC_APP_URL;
  if(!apiKey||!from||!appUrl) fail(503,'Email invitations need RESEND_API_KEY, INVITATION_FROM and PUBLIC_APP_URL server settings');
  let base; try { base=new URL(appUrl); } catch { fail(500,'PUBLIC_APP_URL must be a valid absolute URL'); }
  if(!['http:','https:'].includes(base.protocol)) fail(500,'PUBLIC_APP_URL must use HTTP or HTTPS');
  const link=new URL('/',base); link.searchParams.set('activation',token);
  const safeName=escapeHtml(name), safeLink=escapeHtml(link.href);
  const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'authorization':`Bearer ${apiKey}`,'content-type':'application/json'},body:JSON.stringify({from,to:[email],subject:'Activez votre compte — Gestion de stock',html:`<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#263c5c"><h2>Bonjour ${safeName},</h2><p>Votre compte Gestion de stock a été créé. Cliquez sur le bouton ci-dessous pour choisir votre mot de passe et activer votre accès.</p><p><a href="${safeLink}" style="display:inline-block;background:#2390cb;color:white;padding:12px 18px;border-radius:8px;text-decoration:none">Activer mon compte</a></p><p>Ce lien expire dans 48 heures et ne peut être utilisé qu’une fois.</p><p>Si vous n’attendiez pas cette invitation, ignorez cet e-mail.</p></div>`,text:`Bonjour ${name},\n\nVotre compte Gestion de stock a été créé. Pour choisir votre mot de passe et activer votre accès, ouvrez ce lien (valable 48 heures) :\n${link.href}\n\nSi vous n’attendiez pas cette invitation, ignorez cet e-mail.`})});
  if(!response.ok){const detail=await response.text().catch(()=> '');throw Object.assign(new Error(`Email sending failed (${response.status})${detail?`: ${detail.slice(0,300)}`:''}`),{status:502});}
}

export async function handle(req,res) {
  try {
    const url=new URL(req.url,'http://localhost');
    if (req.method==='GET' && url.pathname==='/api/health') return send(res,200,{ok:true});
    if (['POST','PUT','PATCH','DELETE'].includes(req.method)) ensureSameOrigin(req);
    if (req.method==='POST' && url.pathname==='/api/auth/login') {
      const {email,password}=await body(req); const user=db.prepare('SELECT * FROM users WHERE email=? COLLATE NOCASE').get(String(email||''));
      if (!user || !user.active || !await verifyPassword(String(password||''),user.password_salt,user.password_hash)) return send(res,401,{error:'Email ou mot de passe incorrect.'});
      const token=randomBytes(32).toString('base64url'), now=Math.floor(Date.now()/1000); db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hashToken(token),user.id,now+sessionSeconds,now); db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(user.id);
      return send(res,200,{user:safeUser(user.id),permissions:permissions(user.id)},{'set-cookie':sessionCookie(req,token)});
    }
    if (req.method==='POST' && url.pathname==='/api/auth/activate') {
      const {token,password}=await body(req); if(typeof token!=='string'||!token||typeof password!=='string'||password.length<12)fail(400,'Activation link and a password of at least 12 characters are required');
      const invitation=db.prepare('SELECT user_id FROM user_invitations WHERE token_hash=? AND expires_at>?').get(hashToken(token),Math.floor(Date.now()/1000)); if(!invitation)fail(400,'Invitation link is invalid or expired');
      const p=await passwordFields(password),sessionToken=randomBytes(32).toString('base64url'),now=Math.floor(Date.now()/1000);
      const activated=transaction(()=>{const current=db.prepare('SELECT id FROM user_invitations WHERE user_id=? AND token_hash=? AND expires_at>?').get(invitation.user_id,hashToken(token),now);if(!current)return false;db.prepare('UPDATE users SET password_hash=?,password_salt=?,active=1,last_login=CURRENT_TIMESTAMP WHERE id=?').run(p.passwordHash,p.salt,invitation.user_id);db.prepare('DELETE FROM user_invitations WHERE user_id=?').run(invitation.user_id);db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hashToken(sessionToken),invitation.user_id,now+sessionSeconds,now);return true;});
      if(!activated)fail(400,'Invitation link is invalid or expired'); return send(res,200,{user:safeUser(invitation.user_id),permissions:permissions(invitation.user_id)},{'set-cookie':sessionCookie(req,sessionToken)});
    }
    if (req.method==='POST' && url.pathname==='/api/auth/logout') { const token=parseCookies(req.headers.cookie)[cookieName]; if(token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token)); return send(res,200,{ok:true},{'set-cookie':sessionCookie(req,'',0)}); }
    if (req.method==='GET' && url.pathname==='/api/auth/me') { const u=requireAuth(req); return send(res,200,{user:safeUser(u.id),permissions:permissions(u.id)}); }
    const user=requireAuth(req);
    if (req.method==='GET' && url.pathname==='/api/state') { const out={}; for(const key of Object.keys(stateMap)){ if(stateMap[key].every(s=>has(user.id,s,'view'))) out[key]=JSON.parse(db.prepare('SELECT value FROM app_state WHERE key=?').get(key)?.value || '[]'); else out[key]=[]; }out._version=Number(db.prepare("SELECT value FROM app_meta WHERE key='state_revision'").get().value);return send(res,200,out); }
    if (req.method==='PUT' && url.pathname==='/api/state') {
      const next=await body(req);let changed=false,version=0;transaction(()=>{version=Number(db.prepare("SELECT value FROM app_meta WHERE key='state_revision'").get().value);if(Number(next._version)!==version)fail(409,'Stock data changed in another session. Reload before saving.');for(const [key,sections] of Object.entries(stateMap)){ if(!(key in next)) continue; const old=JSON.parse(db.prepare('SELECT value FROM app_state WHERE key=?').get(key)?.value || '[]'); const incoming=next[key]; if(!Array.isArray(incoming)) fail(400,`Invalid collection: ${key}`);const value=normalizeRows(old,incoming); if(JSON.stringify(old)===JSON.stringify(value)) continue; const actions=changedActions(key,old,value); for(const section of sections){requirePermission(user,section,'view');for(const action of actions)requirePermission(user,section,action);} db.prepare('INSERT INTO app_state(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP').run(key,JSON.stringify(value));changed=true;}if(changed){version++;db.prepare("UPDATE app_meta SET value=? WHERE key='state_revision'").run(String(version));}}); return send(res,200,{ok:true,version});
    }
    if (url.pathname==='/api/admin/users' && req.method==='GET') { requirePermission(user,'users','view'); const users=db.prepare('SELECT u.id,u.name,u.email,u.active,u.last_login AS lastLogin,u.created_at AS createdAt,EXISTS(SELECT 1 FROM user_invitations i WHERE i.user_id=u.id) AS invitationPending FROM users u ORDER BY u.name').all(); return send(res,200,{users:users.map(u=>({...u,invitationPending:Boolean(u.invitationPending),roles:userRoles(u.id)}))}); }
    if (url.pathname==='/api/admin/roles' && req.method==='GET') { requirePermission(user,'users','view'); const all=db.prepare('SELECT id,name FROM roles ORDER BY id').all().map(r=>({...r,permissions:db.prepare('SELECT section,action FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? ORDER BY section,action').all(r.id)})); return send(res,200,{roles:all,catalog}); }
    if (url.pathname==='/api/admin/users' && req.method==='POST') { requirePermission(user,'users','create'); const x=await body(req), firstName=String(x.firstName||'').trim(),lastName=String(x.lastName||'').trim(),name=String(x.name||`${firstName} ${lastName}`).trim(),email=String(x.email||'').trim().toLowerCase(),roleNames=Array.isArray(x.roles)?x.roles:[x.role]; if(!firstName||!lastName||!/^\S+@\S+\.\S+$/.test(email)||!roleNames.length||roleNames.some(r=>!roles.includes(r)))fail(400,'First name, last name, valid email and valid role are required'); if(roleNames.includes('Super Admin')&&!userRoles(user.id).includes('Super Admin'))fail(403,'Only a Super Admin can assign that role'); if(db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(email))fail(409,'An account already uses this email'); const token=randomBytes(32).toString('base64url'), expiry=Math.floor(Date.now()/1000)+48*60*60,p=await passwordFields(randomBytes(48).toString('base64url')); let id; try {id=Number(db.prepare('INSERT INTO users(name,email,password_hash,password_salt,active) VALUES(?,?,?,?,0)').run(name,email,p.passwordHash,p.salt).lastInsertRowid);const link=db.prepare('SELECT id FROM roles WHERE name=?');for(const r of new Set(roleNames))db.prepare('INSERT INTO user_roles(user_id,role_id) VALUES(?,?)').run(id,link.get(r).id);db.prepare('INSERT INTO user_invitations(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)').run(id,hashToken(token),expiry,Math.floor(Date.now()/1000));await sendInvitationEmail({email,name,token});} catch(e) {if(id)db.prepare('DELETE FROM users WHERE id=?').run(id);if(e.status)throw e;if(String(e.message).includes('UNIQUE'))fail(409,'An account already uses this email');throw e;} return send(res,201,{user:safeUser(id),invitationPending:true}); }
    const inviteMatch=url.pathname.match(/^\/api\/admin\/users\/(\d+)\/invitation$/);
    if(inviteMatch&&req.method==='POST'){requirePermission(user,'users','update');const id=Number(inviteMatch[1]),target=safeUser(id);if(!target)fail(404,'User not found');const pending=db.prepare('SELECT user_id FROM user_invitations WHERE user_id=?').get(id);if(!pending||db.prepare('SELECT active FROM users WHERE id=?').get(id).active)fail(409,'This account is not waiting for activation');const token=randomBytes(32).toString('base64url'),expiry=Math.floor(Date.now()/1000)+48*60*60;await sendInvitationEmail({email:target.email,name:target.name,token});db.prepare('UPDATE user_invitations SET token_hash=?,expires_at=?,created_at=? WHERE user_id=?').run(hashToken(token),expiry,Math.floor(Date.now()/1000),id);return send(res,200,{ok:true});}
    const userMatch=url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
    if(userMatch && ['PATCH','DELETE'].includes(req.method)){ requirePermission(user,'users',req.method==='DELETE'?'delete':'update'); const id=Number(userMatch[1]), target=safeUser(id); if(!target) fail(404,'User not found'); const x=req.method==='PATCH'?await body(req):{}; const newRoles=req.method==='PATCH'?(Array.isArray(x.roles)?x.roles:(x.role?[x.role]:target.roles)):[]; if(newRoles.includes('Super Admin')&&!target.roles.includes('Super Admin')&&!userRoles(user.id).includes('Super Admin'))fail(403,'Only a Super Admin can assign that role'); const pending=Boolean(db.prepare('SELECT user_id FROM user_invitations WHERE user_id=?').get(id));if(req.method==='PATCH'&&pending&&x.active===true)fail(409,'The user must activate the account from the invitation link first'); const losesSuper=target.roles.includes('Super Admin')&&!newRoles.includes('Super Admin')||req.method==='DELETE'&&target.roles.includes('Super Admin')||req.method==='PATCH'&&x.active===false&&target.roles.includes('Super Admin'); if(losesSuper && target.active && activeSuperAdmins()<=1) fail(409,'Cannot remove or disable the last active Super Admin'); if(req.method==='DELETE'){db.prepare('DELETE FROM users WHERE id=?').run(id);return send(res,200,{ok:true});} if(newRoles.some(r=>!roles.includes(r))||!newRoles.length) fail(400,'At least one valid role is required'); const active=x.active===undefined?db.prepare('SELECT active FROM users WHERE id=?').get(id).active:Number(Boolean(x.active)); db.prepare('UPDATE users SET name=COALESCE(?,name),email=COALESCE(?,email),active=? WHERE id=?').run(x.name?String(x.name).trim():null,x.email?String(x.email).trim().toLowerCase():null,active,id); db.prepare('DELETE FROM user_roles WHERE user_id=?').run(id); const rs=db.prepare('SELECT id FROM roles WHERE name=?'); for(const r of new Set(newRoles)) db.prepare('INSERT INTO user_roles(user_id,role_id) VALUES(?,?)').run(id,rs.get(r).id); return send(res,200,{user:safeUser(id)}); }
    const resetMatch=url.pathname.match(/^\/api\/admin\/users\/(\d+)\/password$/);
    if(resetMatch && req.method==='POST'){requirePermission(user,'users','update');const id=Number(resetMatch[1]);if(!userRecord(id))fail(404,'User not found');const {password}=await body(req);if(String(password||'').length<12)fail(400,'Password must be at least 12 characters');const p=await passwordFields(password);db.prepare('UPDATE users SET password_hash=?,password_salt=? WHERE id=?').run(p.passwordHash,p.salt,id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);return send(res,200,{ok:true});}
    if(url.pathname==='/api/admin/roles/permissions' && req.method==='PUT'){if(!userRoles(user.id).includes('Super Admin'))fail(403,'Super Admin required to change role permissions');const x=await body(req),r=db.prepare('SELECT id,name FROM roles WHERE name=?').get(x.role);if(!r||!Array.isArray(x.permissions))fail(400,'Invalid role permissions');if(r.name==='Super Admin')fail(409,'Super Admin permissions are immutable');const known=new Set(db.prepare('SELECT section||\'.\'||action k FROM permissions').all().map(p=>p.k));if(x.permissions.some(p=>!known.has(`${p.section}.${p.action}`)))fail(400,'Unknown permission');transaction(()=>{db.prepare('DELETE FROM role_permissions WHERE role_id=?').run(r.id);const ins=db.prepare('INSERT INTO role_permissions(role_id,permission_id) SELECT ?,id FROM permissions WHERE section=? AND action=?');for(const p of x.permissions)ins.run(r.id,p.section,p.action)});return send(res,200,{ok:true});}
    if(url.pathname==='/api/migration/import' && req.method==='POST'){requirePermission(user,'users','update');if(!userRoles(user.id).includes('Super Admin'))fail(403,'Super Admin required');const x=await body(req);for(const k of Object.keys(stateMap))if(!Array.isArray(x[k]))fail(400,`Missing collection: ${k}`);let version=0;transaction(()=>{for(const k of Object.keys(stateMap)){const rows=x[k].map((row,i)=>({...row,id:row.id||`migration-${k}-${i}-${randomUUID()}`}));db.prepare('INSERT INTO app_state(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP').run(k,JSON.stringify(rows));}version=Number(db.prepare("SELECT value FROM app_meta WHERE key='state_revision'").get().value)+1;db.prepare("UPDATE app_meta SET value=? WHERE key='state_revision'").run(String(version));});return send(res,200,{ok:true,version,message:'Migration imported'});}
    return send(res,404,{error:'Not found'});
  } catch(e) { return send(res,e.status||500,{error:e.status?e.message:'Internal server error'}); }
}

export function bootstrapAdmin(email,password,name='Super Admin') {
  if(!email || !password || String(password).length<12) throw new Error('Provide email and a password of at least 12 characters');
  if(db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(email)) throw new Error('Email already exists');
  const pSyncSalt=randomBytes(16).toString('hex');
  // Bootstrap uses the same scrypt format as normal user creation.
  return scrypt(password,pSyncSalt,64).then(hash=>{const id=db.prepare('INSERT INTO users(name,email,password_hash,password_salt) VALUES(?,?,?,?)').run(name,email,hash.toString('hex'),pSyncSalt).lastInsertRowid;const role=db.prepare("SELECT id FROM roles WHERE name='Super Admin'").get();db.prepare('INSERT INTO user_roles(user_id,role_id) VALUES(?,?)').run(id,role.id);return id;});
}

export const server=createServer((req,res)=>{
  if(req.url.startsWith('/api/')) { handle(req,res); return; }
  const requested=new URL(req.url,'http://localhost').pathname;
  if(requested!=='/') {res.writeHead(404);res.end('Not found');return;}
  const file=resolve(root,'outputs/Gestion de stock.html');
  if(!existsSync(file)){res.writeHead(404);res.end('Application not built');return;}
  res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});res.end(readFileSync(file));
});
if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if (process.env.BOOTSTRAP_ADMIN_EMAIL && process.env.BOOTSTRAP_ADMIN_PASSWORD && db.prepare('SELECT COUNT(*) n FROM users').get().n===0) {
    await bootstrapAdmin(process.env.BOOTSTRAP_ADMIN_EMAIL,process.env.BOOTSTRAP_ADMIN_PASSWORD,process.env.BOOTSTRAP_ADMIN_NAME||'Super Admin');
    console.log('Initial Super Admin created. Remove bootstrap environment variables now.');
  }
  server.listen(port,host,()=>console.log(`Stock API listening on http://${host}:${port}`));
}

