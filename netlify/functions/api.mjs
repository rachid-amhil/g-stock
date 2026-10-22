import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const cookieName = 'stock_session';
const sessionSeconds = 8 * 60 * 60;
const invitationSeconds = 48 * 60 * 60;
const stateMap = { inventory: ['products', 'stock'], movements: ['sales', 'stock'], loans: ['stock'], office: ['products', 'stock'] };
const catalog = Object.fromEntries(['products','stock','purchases','sales','suppliers','customers','reports','users'].map(s => [s,['view','create','update','delete']]));
const roleNames = ['Super Admin','Admin','Magasinier','Consultation'];

function fail(status, message) { const error = new Error(message); error.status = status; throw error; }
function hashToken(token) { return createHash('sha256').update(token).digest('hex'); }
function parseCookies(header = '') { return Object.fromEntries(header.split(';').map(x => x.trim().split('=').map(decodeURIComponent)).filter(x => x.length === 2)); }
function json(statusCode, body, headers = {}) { return { statusCode, headers: { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', ...headers }, body: JSON.stringify(body) }; }
function cookie(token, maxAge = sessionSeconds) { return `${cookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}; Secure`; }
function parseBody(event) { try { const raw = event.body || '{}'; if (Buffer.byteLength(raw) > 2_000_000) fail(413,'Request too large'); return JSON.parse(raw); } catch (e) { if (e.status) throw e; fail(400,'Invalid JSON'); } }
function getPath(event) { return event.queryStringParameters?.path || event.path?.replace(/^\/.netlify\/functions\/api/, '') || '/'; }
function sameOrigin(event) { const origin = event.headers?.origin; if (!origin) return; const host = event.headers?.['x-forwarded-host'] || event.headers?.host; if (host && ![`${event.headers?.['x-forwarded-proto'] || 'https'}://${host}`,`https://${host}`].includes(origin)) fail(403,'Cross-origin request rejected'); }

function config() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) fail(503,'Supabase server settings are missing. Configure SUPABASE_URL and SUPABASE_SECRET_KEY in Netlify.');
  return { url: url.replace(/\/$/, ''), key };
}
async function rest(path, { method='GET', body, prefer } = {}) {
  const { url, key } = config();
  const headers = { apikey:key, authorization:`Bearer ${key}`, 'content-type':'application/json' };
  if (prefer) headers.Prefer = prefer;
  const response = await fetch(`${url}/rest/v1/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const raw = await response.text();
  let result = null;
  try { result = raw ? JSON.parse(raw) : null; } catch { result = raw; }
  if (!response.ok) {
    const message = result?.message || result?.hint || `Supabase request failed (${response.status})`;
    const status = response.status === 409 && String(result?.code || '') === '40001' ? 409 : 502;
    const error = new Error(message); error.status = status; throw error;
  }
  return result;
}
async function rpc(name, params) {
  return rest(`rpc/${name}`, { method:'POST', body:params, prefer:'return=representation' });
}
async function selectUserByEmail(email) {
  const rows = await rest(`users?email=eq.${encodeURIComponent(email)}&select=*`);
  return rows?.[0] || null;
}
async function userRecord(id) {
  const rows = await rest(`users?id=eq.${encodeURIComponent(id)}&select=id,name,email,active,last_login,created_at`);
  return rows?.[0] || null;
}
async function userRoles(id) {
  const rows = await rest(`user_roles?user_id=eq.${encodeURIComponent(id)}&select=role:roles(name)`);
  return (rows || []).map(x => x.role?.name).filter(Boolean);
}
async function safeUser(id) {
  const user = await userRecord(id);
  return user ? { id:user.id, name:user.name, email:user.email, active:user.active, lastLogin:user.last_login, createdAt:user.created_at, roles:await userRoles(id) } : null;
}
async function permissions(id) {
  const ur = await rest(`user_roles?user_id=eq.${encodeURIComponent(id)}&select=role_id`);
  if (!ur?.length) return [];
  const ids = ur.map(x => x.role_id).join(',');
  const links = await rest(`role_permissions?role_id=in.(${ids})&select=permission:permissions(section,action)`);
  const distinct = new Map();
  for (const row of links || []) if (row.permission) distinct.set(`${row.permission.section}.${row.permission.action}`,row.permission);
  return [...distinct.values()];
}
async function userFromEvent(event) {
  const token = parseCookies(event.headers?.cookie || '')[cookieName];
  if (!token) return null;
  const rows = await rest(`sessions?token_hash=eq.${hashToken(token)}&expires_at=gt.${Math.floor(Date.now()/1000)}&select=user_id`);
  if (!rows?.length) return null;
  const user = await userRecord(rows[0].user_id);
  return user?.active ? user : null;
}
function requirePermission(permissionsList, section, action) {
  if (!permissionsList.some(p => p.section === section && p.action === action)) fail(403,`Missing permission: ${section}.${action}`);
}
async function authorization(event) {
  const user = await userFromEvent(event);
  if (!user) fail(401,'Authentication required');
  return { user, roles:await userRoles(user.id), permissions:await permissions(user.id) };
}
function identity(row) {
  if (row?.id !== undefined && row?.id !== null) return `id:${row.id}`;
  if (row?.serial) return `serial:${row.serial}`;
  if (row?.type || row?.reference || row?.brand) return `item:${row.type||''}|${row.reference||''}|${row.brand||''}`;
  return `value:${JSON.stringify(row)}`;
}
function businessIdentity(row) {
  if (row?.serial) return `serial:${row.serial}`;
  if (row?.type || row?.reference || row?.brand) return `item:${row.type||''}|${row.reference||''}|${row.brand||''}`;
  return `value:${JSON.stringify(row)}`;
}
function normalizeRows(oldRows, newRows) {
  const available = new Set(oldRows.map((_,i)=>i));
  return newRows.map(row => {
    let index = row?.id == null ? -1 : oldRows.findIndex((x,i)=>available.has(i)&&String(x.id)===String(row.id));
    if (index < 0) index = oldRows.findIndex((x,i)=>available.has(i)&&JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k])=>k!=='id')))===JSON.stringify(Object.fromEntries(Object.entries(row||{}).filter(([k])=>k!=='id'))));
    if (index < 0) index = oldRows.findIndex((x,i)=>available.has(i)&&businessIdentity(x)===businessIdentity(row));
    if (index >= 0) { available.delete(index); return { ...row, id:oldRows[index].id??row.id??randomUUID() }; }
    return { ...row, id:row?.id??randomUUID() };
  });
}
function changedActions(oldRows,newRows) {
  const pending = new Map();
  for (const row of oldRows) { const key=identity(row); if(!pending.has(key))pending.set(key,[]); pending.get(key).push(row); }
  const actions = new Set();
  for (const row of newRows) { const group=pending.get(identity(row)); if(!group?.length){actions.add('create');continue;} const old=group.shift(); if(JSON.stringify(old)!==JSON.stringify(row))actions.add('update'); }
  for (const group of pending.values()) if(group.length)actions.add('delete');
  return actions;
}
async function stateRows() {
  const [rows,meta] = await Promise.all([
    rest('app_state?select=key,value'),
    rest('app_meta?key=eq.state_revision&select=value')
  ]);
  const state = Object.fromEntries((rows||[]).map(x=>[x.key,x.value]));
  for (const key of Object.keys(stateMap)) state[key] = Array.isArray(state[key]) ? state[key] : [];
  state._version = Number(meta?.[0]?.value || 0);
  return state;
}
async function sendInvitationEmail({ email, name, token }) {
  const apiKey=process.env.RESEND_API_KEY, from=process.env.INVITATION_FROM, appUrl=process.env.URL || process.env.PUBLIC_APP_URL;
  if(!apiKey||!from||!appUrl)fail(503,'Configure RESEND_API_KEY, INVITATION_FROM and the Netlify site URL to send invitations.');
  const link=new URL('/',appUrl);link.searchParams.set('activation',token);
  const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:`Bearer ${apiKey}`,'content-type':'application/json'},body:JSON.stringify({from,to:[email],subject:'Activez votre compte — Gestion de stock',html:`<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#263c5c"><h2>Bonjour ${esc(name)},</h2><p>Votre compte Gestion de stock a été créé. Cliquez pour choisir votre mot de passe et activer votre accès.</p><p><a href="${esc(link.href)}" style="background:#2390cb;color:white;padding:12px 18px;border-radius:8px;text-decoration:none">Activer mon compte</a></p><p>Ce lien expire dans 48 heures et ne peut être utilisé qu’une fois.</p></div>`,text:`Bonjour ${name},\n\nActivez votre compte avec ce lien (valable 48 heures) :\n${link.href}`})});
  if(!response.ok)fail(502,`Email sending failed (${response.status})`);
}
async function bootstrapAdmin() {
  const rows=await rest('users?select=id&limit=1');
  if(rows?.length)return;
  const email=process.env.BOOTSTRAP_ADMIN_EMAIL,password=process.env.BOOTSTRAP_ADMIN_PASSWORD,name=process.env.BOOTSTRAP_ADMIN_NAME||'Super Admin';
  if(!email&&!password)return;
  if(!email||!password||String(password).length<12)fail(503,'Set a valid BOOTSTRAP_ADMIN_EMAIL and a BOOTSTRAP_ADMIN_PASSWORD of at least 12 characters in Netlify.');
  const role=await rest(`roles?name=eq.${encodeURIComponent('Super Admin')}&select=id`);
  if(!role?.length)fail(503,'Apply the Supabase migration before the first login.');
  const salt=randomBytes(16).toString('hex'),hash=(await scrypt(password,salt,64)).toString('hex');
  const created=await rest('users',{method:'POST',body:{name,email:email.toLowerCase(),password_hash:hash,password_salt:salt,active:true},prefer:'return=representation'});
  await rest('user_roles',{method:'POST',body:{user_id:created[0].id,role_id:role[0].id},prefer:'return=minimal'});
}

export async function handler(event) {
  try {
    const path=getPath(event), method=event.httpMethod||'GET';
    if(method==='GET'&&path==='/api/health')return json(200,{ok:true});
    if(['POST','PUT','PATCH','DELETE'].includes(method))sameOrigin(event);
    if(!path.startsWith('/api/'))return json(404,{error:'Not found'});
    await bootstrapAdmin();

    if(method==='POST'&&path==='/api/auth/login'){
      const x=parseBody(event),user=await selectUserByEmail(String(x.email||'').trim().toLowerCase());
      if(!user||!user.active||!await verifyPassword(String(x.password||''),user.password_salt,user.password_hash))return json(401,{error:'Email ou mot de passe incorrect.'});
      const token=randomBytes(32).toString('base64url'),now=Math.floor(Date.now()/1000);
      await rest('sessions',{method:'POST',body:{token_hash:hashToken(token),user_id:user.id,expires_at:now+sessionSeconds,created_at:now},prefer:'return=minimal'});
      await rest(`users?id=eq.${user.id}`,{method:'PATCH',body:{last_login:new Date().toISOString()},prefer:'return=minimal'});
      return json(200,{user:await safeUser(user.id),permissions:await permissions(user.id)},{'set-cookie':cookie(token)});
    }
    if(method==='POST'&&path==='/api/auth/activate'){
      const x=parseBody(event);if(typeof x.token!=='string'||!x.token||typeof x.password!=='string'||x.password.length<12)fail(400,'Activation link and a password of at least 12 characters are required');
      const salt=randomBytes(16).toString('hex'),hash=(await scrypt(x.password,salt,64)).toString('hex'),token=randomBytes(32).toString('base64url'),now=Math.floor(Date.now()/1000);
      const ids=await rpc('activate_invitation',{p_token_hash:hashToken(x.token),p_password_hash:hash,p_password_salt:salt,p_session_token_hash:hashToken(token),p_expires_at:now+sessionSeconds,p_now:now});
      const id=Array.isArray(ids)?ids[0]:ids;if(!id)fail(400,'Invitation link is invalid or expired');
      return json(200,{user:await safeUser(id),permissions:await permissions(id)},{'set-cookie':cookie(token)});
    }
    if(method==='POST'&&path==='/api/auth/logout'){
      const token=parseCookies(event.headers?.cookie||'')[cookieName];if(token)await rest(`sessions?token_hash=eq.${hashToken(token)}`,{method:'DELETE'});
      return json(200,{ok:true},{'set-cookie':cookie('',0)});
    }
    if(method==='GET'&&path==='/api/auth/me'){
      const {user}=await authorization(event);return json(200,{user:await safeUser(user.id),permissions:await permissions(user.id)});
    }
    const auth=await authorization(event),{user,roles,permissions:perms}=auth;
    if(method==='GET'&&path==='/api/state'){
      const result=await stateRows();for(const [key,sections] of Object.entries(stateMap))if(!sections.every(s=>perms.some(p=>p.section===s&&p.action==='view')))result[key]=[];
      return json(200,result);
    }
    if(method==='PUT'&&path==='/api/state'){
      const next=parseBody(event),old=await stateRows();if(Number(next._version)!==old._version)fail(409,'Stock data changed in another session. Reload before saving.');
      const save={};let changed=false;
      for(const [key,sections] of Object.entries(stateMap)){
        if(!(key in next))continue;if(!Array.isArray(next[key]))fail(400,`Invalid collection: ${key}`);
        const normalized=normalizeRows(old[key],next[key]),actions=changedActions(old[key],normalized);
        if(!actions.size){save[key]=old[key];continue;}
        for(const section of sections){requirePermission(perms,section,'view');for(const action of actions)requirePermission(perms,section,action);}
        save[key]=normalized;changed=true;
      }
      if(!changed)return json(200,{ok:true,version:old._version});
      const result=await rpc('apply_app_state',{p_state:save,p_expected_revision:old._version});
      return json(200,{ok:true,version:Number(Array.isArray(result)?result[0]:result)});
    }
    if(method==='GET'&&path==='/api/admin/users'){
      requirePermission(perms,'users','view');const users=await rest('users?select=id,name,email,active,last_login,created_at&order=name');
      const invitations=await rest(`user_invitations?select=user_id&expires_at=gt.${Math.floor(Date.now()/1000)}`),pending=new Set((invitations||[]).map(x=>String(x.user_id)));
      return json(200,{users:await Promise.all((users||[]).map(async u=>({id:u.id,name:u.name,email:u.email,active:u.active,lastLogin:u.last_login,createdAt:u.created_at,invitationPending:pending.has(String(u.id)),roles:await userRoles(u.id)})))});
    }
    if(method==='GET'&&path==='/api/admin/roles'){
      requirePermission(perms,'users','view');const all=await rest('roles?select=id,name&order=id');
      const rolesOut=await Promise.all((all||[]).map(async r=>{const links=await rest(`role_permissions?role_id=eq.${r.id}&select=permission_id,permission:permissions(section,action)`);return {...r,permissions:(links||[]).map(x=>x.permission).filter(Boolean)}}));
      return json(200,{roles:rolesOut,catalog});
    }
    if(method==='POST'&&path==='/api/admin/users'){
      requirePermission(perms,'users','create');const x=parseBody(event),first=String(x.firstName||'').trim(),last=String(x.lastName||'').trim(),name=String(x.name||`${first} ${last}`).trim(),email=String(x.email||'').trim().toLowerCase(),chosen=Array.isArray(x.roles)?x.roles:[x.role];
      if(!first||!last||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!chosen.length||chosen.some(r=>!roleNames.includes(r)))fail(400,'First name, last name, valid email and role are required');
      if(chosen.includes('Super Admin')&&!roles.includes('Super Admin'))fail(403,'Only a Super Admin can assign that role');
      if(await selectUserByEmail(email))fail(409,'An account already uses this email');
      const token=randomBytes(32).toString('base64url'),now=Math.floor(Date.now()/1000),salt=randomBytes(16).toString('hex'),hash=(await scrypt(randomBytes(48).toString('base64url'),salt,64)).toString('hex');let id;
      try{
        const created=await rest('users',{method:'POST',body:{name,email,password_hash:hash,password_salt:salt,active:false},prefer:'return=representation'});id=created[0].id;
        const roleRows=await rest(`roles?name=in.(${[...new Set(chosen)].map(encodeURIComponent).join(',')})&select=id,name`);
        await rest('user_roles',{method:'POST',body:roleRows.map(r=>({user_id:id,role_id:r.id})),prefer:'return=minimal'});
        await rest('user_invitations',{method:'POST',body:{user_id:id,token_hash:hashToken(token),expires_at:now+invitationSeconds,created_at:now},prefer:'return=minimal'});
        await sendInvitationEmail({email,name,token});
      }catch(e){if(id)await rest(`users?id=eq.${id}`,{method:'DELETE'}).catch(()=>{});if(e.status)throw e;if(String(e.message).includes('duplicate'))fail(409,'An account already uses this email');throw e;}
      return json(201,{user:await safeUser(id),invitationPending:true});
    }
    const inviteMatch=path.match(/^\/api\/admin\/users\/(\d+)\/invitation$/);
    if(inviteMatch&&method==='POST'){
      requirePermission(perms,'users','update');const id=inviteMatch[1],target=await safeUser(id);if(!target)fail(404,'User not found');
      const pending=await rest(`user_invitations?user_id=eq.${id}&select=user_id`);if(!pending?.length||target.active)fail(409,'This account is not waiting for activation');
      const token=randomBytes(32).toString('base64url'),now=Math.floor(Date.now()/1000);await sendInvitationEmail({email:target.email,name:target.name,token});
      await rest(`user_invitations?user_id=eq.${id}`,{method:'PATCH',body:{token_hash:hashToken(token),expires_at:now+invitationSeconds,created_at:now},prefer:'return=minimal'});return json(200,{ok:true});
    }
    const userMatch=path.match(/^\/api\/admin\/users\/(\d+)$/);
    if(userMatch&&['PATCH','DELETE'].includes(method)){
      requirePermission(perms,'users',method==='DELETE'?'delete':'update');const id=userMatch[1],target=await safeUser(id);if(!target)fail(404,'User not found');const x=method==='PATCH'?parseBody(event):{},newRoles=method==='PATCH'?(Array.isArray(x.roles)?x.roles:x.role?[x.role]:target.roles):[];
      if(newRoles.includes('Super Admin')&&!target.roles.includes('Super Admin')&&!roles.includes('Super Admin'))fail(403,'Only a Super Admin can assign that role');
      const invitation=await rest(`user_invitations?user_id=eq.${id}&select=user_id`);if(method==='PATCH'&&invitation?.length&&x.active===true)fail(409,'The user must activate the account from the invitation link first');
      const losesSuper=target.roles.includes('Super Admin')&&(!newRoles.includes('Super Admin')||method==='DELETE'||x.active===false);
      if(losesSuper&&target.active){const active=await rest('users?active=eq.true&select=id,user_roles(role:roles(name))');const count=(active||[]).filter(u=>(u.user_roles||[]).some(a=>a.role?.name==='Super Admin')).length;if(count<=1)fail(409,'Cannot remove or disable the last active Super Admin');}
      if(method==='DELETE'){await rest(`users?id=eq.${id}`,{method:'DELETE'});return json(200,{ok:true});}
      if(!newRoles.length||newRoles.some(r=>!roleNames.includes(r)))fail(400,'At least one valid role is required');
      await rest(`users?id=eq.${id}`,{method:'PATCH',body:{...(x.name?{name:String(x.name).trim()}:{}),...(x.email?{email:String(x.email).trim().toLowerCase()}:{}),...(x.active===undefined?{}:{active:Boolean(x.active)})},prefer:'return=minimal'});
      const ids=await rest(`roles?name=in.(${[...new Set(newRoles)].map(encodeURIComponent).join(',')})&select=id`);await rpc('set_user_roles',{p_user_id:id,p_role_ids:ids.map(r=>r.id)});if(x.active===false)await rest(`sessions?user_id=eq.${id}`,{method:'DELETE'});return json(200,{user:await safeUser(id)});
    }
    const resetMatch=path.match(/^\/api\/admin\/users\/(\d+)\/password$/);
    if(resetMatch&&method==='POST'){
      requirePermission(perms,'users','update');const id=resetMatch[1];if(!await userRecord(id))fail(404,'User not found');const {password}=parseBody(event);if(String(password||'').length<12)fail(400,'Password must be at least 12 characters');const salt=randomBytes(16).toString('hex'),hash=(await scrypt(password,salt,64)).toString('hex');await rest(`users?id=eq.${id}`,{method:'PATCH',body:{password_hash:hash,password_salt:salt},prefer:'return=minimal'});await rest(`sessions?user_id=eq.${id}`,{method:'DELETE'});return json(200,{ok:true});
    }
    if(path==='/api/admin/roles/permissions'&&method==='PUT'){
      if(!roles.includes('Super Admin'))fail(403,'Super Admin required to change role permissions');const x=parseBody(event),role=(await rest(`roles?name=eq.${encodeURIComponent(x.role)}&select=id,name`))?.[0];if(!role||!Array.isArray(x.permissions))fail(400,'Invalid role permissions');if(role.name==='Super Admin')fail(409,'Super Admin permissions are immutable');
      if(x.permissions.some(p=>!catalog[p.section]?.includes(p.action)))fail(400,'Unknown permission');await rpc('set_role_permissions',{p_role_id:role.id,p_permissions:x.permissions});return json(200,{ok:true});
    }
    if(path==='/api/migration/import'&&method==='POST'){
      requirePermission(perms,'users','update');if(!roles.includes('Super Admin'))fail(403,'Super Admin required');const x=parseBody(event);for(const key of Object.keys(stateMap))if(!Array.isArray(x[key]))fail(400,`Missing collection: ${key}`);
      const old=await stateRows(),state={};for(const key of Object.keys(stateMap))state[key]=x[key].map((row,i)=>({...row,id:row.id||`migration-${key}-${i}-${randomUUID()}`}));const result=await rpc('apply_app_state',{p_state:state,p_expected_revision:old._version});return json(200,{ok:true,version:Number(Array.isArray(result)?result[0]:result),message:'Migration imported'});
    }
    return json(404,{error:'Not found'});
  } catch(error) { return json(error.status||500,{error:error.status?error.message:'Internal server error'}); }
}

async function verifyPassword(password,salt,expected){
  try {const actual=await scrypt(password,salt,64),known=Buffer.from(expected,'hex');return actual.length===known.length&&timingSafeEqual(actual,known);}catch{return false;}
}
