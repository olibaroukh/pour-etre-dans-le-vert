// Relais Zimbra pour bilan-passage + repartition_stocks.html — Olivier Baroukh / Optical Center
// Ce Worker retransmet les appels SOAP et l'upload de pièce jointe vers Zimbra
// à côté serveur, pour contourner le blocage CORS du navigateur.
// Il persiste aussi une copie structurée de chaque bilan dans D1 (routes /store-bilan, /bilans)
// pour alimenter l'analyse centralisée, indépendante du localStorage de chaque animateur.

const ALLOWED_ORIGIN = 'https://olibaroukh.github.io';
const ZIMBRA_SOAP_URL = 'https://zimbra.oc-pratique.com/service/soap';
const ZIMBRA_UPLOAD_URL = 'https://zimbra.oc-pratique.com/service/upload?fmt=raw';

// Token secret pour sécuriser la route /notify
// À changer si compromis — doit correspondre à NOTIFY_SECRET dans index.html
const NOTIFY_SECRET = 'OC-bilan-notify-2026';

// Token secret pour sécuriser les routes de persistance D1 (/store-bilan, /bilans)
// À changer si compromis — doit correspondre à STORE_SECRET dans index.html / dashboard
const STORE_SECRET = 'OC-bilan-store-2026';

// Clé de signature interne des sessions animateur (HMAC), jamais exposée côté client
const AR_SESSION_SECRET = 'OC-bilan-arsession-2026-signing-key';
const AR_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const MAGASINS_CSV_URL = 'https://raw.githubusercontent.com/olibaroukh/bilan-passage/main/magasins.csv';

let _magasinsCache = null;
let _magasinsCacheAt = 0;

async function getMagasinsServerSide() {
  const now = Date.now();
  if (_magasinsCache && (now - _magasinsCacheAt) < 10 * 60 * 1000) return _magasinsCache;
  const resp = await fetch(MAGASINS_CSV_URL + '?v=' + now);
  const text = await resp.text();
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = lines[0].split(';').map(h => h.trim());
  const idxAnimateur = header.indexOf('animateur');
  const idxCode = header.indexOf('code');
  const idxEmail = header.indexOf('animateur_email');
  const rows = lines.slice(1).map(line => {
    const cols = line.split(';');
    return {
      code: (cols[idxCode] || '').trim(),
      animateur: (cols[idxAnimateur] || '').trim(),
      animateurEmail: idxEmail >= 0 ? (cols[idxEmail] || '').trim() : '',
    };
  }).filter(r => r.code);
  _magasinsCache = rows;
  _magasinsCacheAt = now;
  return rows;
}

function getArEmail(stores, arName) {
  const match = stores.find(s => s.animateur === arName && s.animateurEmail);
  return match ? match.animateurEmail : null;
}

function normalizeName(s) {
  return (s || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '');
}

async function hmacSign(payloadStr) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(AR_SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createArSession(ar) {
  const payload = JSON.stringify({ ar, exp: Date.now() + AR_SESSION_TTL_MS });
  const b64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await hmacSign(b64);
  return b64 + '.' + sig;
}

async function verifyArSession(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expectedSig = await hmacSign(b64);
  if (sig !== expectedSig) return null;
  let payload;
  try { payload = JSON.parse(decodeURIComponent(escape(atob(b64)))); } catch(e) { return null; }
  if (!payload || !payload.ar || !payload.exp || payload.exp < Date.now()) return null;
  return payload.ar;
}

function jsonError(msg, status, corsHeaders) {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
}

function bilanMagasinLabel(b) {
  return b.magasin?.libelle || b.magasin_libelle || '?';
}
function bilanMagasinCode(b) {
  return b.magasin?.code || b.magasin_code || '?';
}

function avgOf(list, field) {
  const vals = list.map(b => b[field]).filter(v => v !== undefined && v !== null && v !== '' && !isNaN(Number(v)));
  return vals.length ? (vals.reduce((a, v) => a + Number(v), 0) / vals.length) : null;
}

function computeArStats(byAR) {
  return Object.entries(byAR).map(([ar, list]) => {
    const magasins = new Set(list.map(bilanMagasinCode));
    return { label: ar, nbBilans: list.length, nbMagasins: magasins.size, avgHumeur: avgOf(list, 'humeur'), avgDuree: avgOf(list, 'duree') };
  });
}

function computeStoreStats(bilansList) {
  const byMagasin = {};
  bilansList.forEach(b => {
    const key = bilanMagasinLabel(b);
    if (!byMagasin[key]) byMagasin[key] = [];
    byMagasin[key].push(b);
  });
  return Object.entries(byMagasin).map(([magasin, list]) => {
    const lastDate = list.map(b => b.date).sort().slice(-1)[0];
    return { label: magasin, nbBilans: list.length, lastDate, avgHumeur: avgOf(list, 'humeur'), avgDuree: avgOf(list, 'duree') };
  });
}

function htmlStatsTable(headers, rows) {
  const th = headers.map(h => `<th style="text-align:left;padding:8px 12px;background:#0D0D0D;color:#F0EDE6;font-family:Arial,Helvetica,sans-serif;font-size:12px">${escapeHtml(h)}</th>`).join('');
  const trs = rows.map((r, i) => {
    const bg = i % 2 === 0 ? '#F5F3EE' : '#FFFFFF';
    const tds = r.map(c => `<td style="padding:7px 12px;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#2C2C2A;border-bottom:1px solid #E5E2DA">${escapeHtml(String(c))}</td>`).join('');
    return `<tr style="background:${bg}">${tds}</tr>`;
  }).join('');
  return `<table style="width:100%;border-collapse:collapse;margin:6px 0 20px"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table>`;
}

function htmlBulletSections(sectionsMap) {
  return Object.entries(sectionsMap).map(([title, bullets]) => {
    const items = (Array.isArray(bullets) ? bullets : [bullets]).map(b => `<li style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#2C2C2A;line-height:1.5;margin-bottom:4px">${escapeHtml(b)}</li>`).join('');
    return `<h3 style="font-family:Arial,Helvetica,sans-serif;color:#CC1719;font-size:14px;margin:16px 0 6px;border-bottom:1px solid #CC1719;padding-bottom:3px">${escapeHtml(title)}</h3><ul style="margin:0 0 4px;padding-left:18px">${items}</ul>`;
  }).join('');
}

function wrapEmailBody(innerHtml) {
  return `<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;margin:0 auto;padding:8px">${innerHtml}</div>`;
}

function resumeBilan(b) {
  const actions = (b.actions || []).map(a => `- [${a.status || 'en cours'}] ${a.label || a.text || JSON.stringify(a)}`).join('\n') || 'Aucune action notée';
  return [
    `Date: ${b.date}${b.passage ? ' (passage n°' + b.passage + ')' : ''}`,
    `Magasin: ${b.magasin?.libelle || b.magasin_libelle || '?'} (${b.magasin?.code || b.magasin_code || '?'})`,
    `Animateur: ${b.ar || '?'}`,
    b.humeur !== undefined && b.humeur !== null ? `Humeur/ambiance (0-10): ${b.humeur}` : '',
    b.renta ? `Rentabilité: ${b.renta}%` : '',
    b.ca_mensuel ? `CA mensuel: ${b.ca_mensuel}` : '',
    b.forts ? `Points forts: ${b.forts}` : '',
    b.diff ? `Difficultés: ${b.diff}` : '',
    `Actions:\n${actions}`,
    b.manager_obs ? `Observations manager: ${b.manager_obs}` : '',
    b.remarque_libre ? `Remarque libre: ${b.remarque_libre}` : '',
  ].filter(Boolean).join('\n');
}

const OLIVIER_EMAIL = 'olivier.baroukh@optical-center.com';
const VANESSA_EMAIL = 'vanessa.baroukh@optical-center.com';

async function purgeWeeklySources(env) {
  // Purge des données brutes hebdomadaires (observations, pour_etre_dans_le_vert).
  // La table `bilans` (Bilan de Passage) n'est JAMAIS purgée — elle alimente l'historique
  // long de l'onglet Analyse et le futur bilan mensuel.
  try { await env.DB.prepare('DELETE FROM observations').run(); } catch(e) { console.error('Purge observations échouée:', e); }
  try { await env.DB.prepare('DELETE FROM store_stats').run(); } catch(e) { console.error('Purge store_stats échouée:', e); }
}

async function generateObsComHebdo(obsList, env) {
  if (!Array.isArray(obsList) || !obsList.length) throw new Error('Aucune observation à traiter');
  if (!env.ANTHROPIC_API_KEY) throw new Error('Clé API Anthropic non configurée sur le Worker');

  const lines = obsList.map(o => `[${o.dl}][${o.m}][${o.th}][${o.t === 'p' ? '+' : '-'}] ${o.tx}`).join('\n');

  const systemPrompt = `Tu aides à préparer la communication hebdomadaire pour 4 magasins Optical Center (Montgeron, Vitry, Quincy, Fresnes) à partir d'observations terrain.

RÈGLES DE STYLE (à respecter strictement) :
- Ton motivant, jamais alarmiste.
- Ne JAMAIS pointer un magasin par son nom sur un point négatif — rester général plutôt que de nommer un magasin en difficulté.
- Convention interne : pour Montgeron, utilise le prénom "Eitan" (son manager) à la place du nom du magasin. Pour Vitry, utilise "Dan". Quincy et Fresnes peuvent être cités normalement.
- Français.

FORMATS ATTENDUS (réponds uniquement en JSON valide, sans texte avant/après, sans balises markdown) :
{
  "slack1": {"titre": "emoji + titre court", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "slack2": {"titre": "emoji + titre court (angle différent de slack1)", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "slack3": {"titre": "emoji + titre court (angle différent de slack1 et slack2)", "contenu": "2-4 phrases", "conclusion": "1 phrase très courte et percutante"},
  "message_general": "message autonome avec emojis, indépendant des 3 Slack (pas de redite), 4-8 phrases, ton motivant",
  "elements_mail": "liste des éléments terrain à intégrer dans le mail (PAS un mail complet rédigé — juste les points/faits marquants de la semaine, en quelques lignes, que l'auteur complètera avec le ton général, les chiffres et infos supplémentaires)"
}`;

  const userPrompt = `Voici les observations terrain de la semaine :\n\n${lines}`;

  const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 1800, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] }),
  });
  const claudeData = await claudeResp.json();
  if (!claudeResp.ok) throw new Error('Erreur API Claude : ' + JSON.stringify(claudeData));

  const rawText = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
  try {
    return JSON.parse(stripJsonFences(rawText));
  } catch (e) {
    throw new Error('Réponse IA non-JSON, impossible à parser : ' + rawText.slice(0, 300));
  }
}

function formatObsEmail(fields) {
  return [
    `--- SLACK 1 ---`, fields.slack1, ``,
    `--- SLACK 2 ---`, fields.slack2, ``,
    `--- SLACK 3 ---`, fields.slack3, ``,
    `--- MESSAGE GÉNÉRAL ---`, fields.messageGeneral, ``,
    `--- ÉLÉMENTS POUR LE MAIL ---`, fields.elementsMail,
    fields.infosSupplementaires ? `\n--- INFOS SUPPLÉMENTAIRES ---\n${fields.infosSupplementaires}` : '',
  ].filter(x => x !== undefined && x !== '').join('\n');
}

function mostRecentWeekRange() {
  // Couvre le lundi -> vendredi le plus récent, peu importe le jour d'exécution (samedi ou dimanche)
  const now = new Date();
  const day = now.getUTCDay(); // 0=dim, 1=lun, ..., 5=ven, 6=sam
  const diffToFriday = ((day - 5) + 7) % 7 || 7; // nombre de jours depuis le dernier vendredi (jamais 0 ici : on tourne sam/dim)
  const friday = new Date(now); friday.setUTCDate(now.getUTCDate() - diffToFriday);
  const monday = new Date(friday); monday.setUTCDate(friday.getUTCDate() - 4);
  const fmt = d => d.toISOString().slice(0, 10);
  return { from: fmt(monday), to: fmt(friday) };
}

async function getWeekData(env, override) {
  const { from, to } = (override && override.from && override.to) ? override : mostRecentWeekRange();
  const { results } = await env.DB.prepare(
    'SELECT * FROM bilans WHERE date >= ? AND date <= ? ORDER BY ar, date'
  ).bind(from, to).all();
  const bilans = results.map(r => { try { return JSON.parse(r.data_json); } catch(e) { return r; } });

  const stores = await getMagasinsServerSide();
  const allARs = [...new Set(stores.map(s => s.animateur).filter(Boolean))].sort();

  const byAR = {};
  allARs.forEach(a => byAR[a] = []);
  bilans.forEach(b => {
    const ar = b.ar || 'Non renseigné';
    if (!byAR[ar]) byAR[ar] = [];
    byAR[ar].push(b);
  });

  return { from, to, bilans, allARs, byAR };
}

function escapeHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function textToHtmlEmail(bodyText) {
  const lines = (bodyText || '').split('\n');
  let html = '';
  let inParagraph = false;
  const closeP = () => { if (inParagraph) { html += '</p>'; inParagraph = false; } };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const sectionMatch = line.match(/^---\s*(.+?)\s*---$/);
    if (sectionMatch) {
      closeP();
      html += `<h3 style="font-family:Arial,Helvetica,sans-serif;color:#CC1719;font-size:15px;margin:22px 0 8px;border-bottom:2px solid #CC1719;padding-bottom:4px">${escapeHtml(sectionMatch[1])}</h3>`;
    } else if (line === '') {
      closeP();
    } else {
      if (!inParagraph) { html += '<p style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.6;color:#2C2C2A;margin:0 0 10px">'; inParagraph = true; }
      else html += '<br>';
      html += escapeHtml(line);
    }
  }
  closeP();

  return `<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;margin:0 auto;padding:8px">${html}</div>`;
}

async function zimbraSendMail(env, { to, subject, bodyText, bodyHtml }) {
  const authResp = await fetch(ZIMBRA_SOAP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
      Body: {
        AuthRequest: {
          _jsns: 'urn:zimbraAccount',
          account: { by: 'name', _content: env.ZIMBRA_CRON_USER },
          password: { _content: env.ZIMBRA_CRON_PASS }
        }
      }
    })
  });
  const authData = await authResp.json();
  const token = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
  if (!token) throw new Error('Authentification Zimbra (compte cron) échouée');

  const sendResp = await fetch(ZIMBRA_SOAP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': `ZM_AUTH_TOKEN=${token}` },
    body: JSON.stringify({
      Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' }, authToken: [{ _content: token }] } },
      Body: {
        SendMsgRequest: {
          _jsns: 'urn:zimbraMail',
          m: { su: { _content: subject }, e: [{ t: 't', a: to }], mp: { ct: 'text/html', content: { _content: bodyHtml || textToHtmlEmail(bodyText) } } }
        }
      }
    })
  });
  if (!sendResp.ok) throw new Error('Envoi email échoué (' + sendResp.status + ')');
}

async function generateWeeklyReport(env, override) {
  const { from, to, bilans, byAR } = await getWeekData(env, override);

  const sections = Object.entries(byAR).map(([ar, list]) => {
    if (!list.length) return `=== ${ar} ===\nAucun bilan de passage enregistré cette semaine.`;
    return `=== ${ar} (${list.length} bilan(s)) ===\n` + list.map(resumeBilan).join('\n\n---\n\n');
  }).join('\n\n\n');

  const systemPrompt = `Tu prépares le bilan hebdomadaire du réseau Optical Center. Pour CHAQUE animateur listé (même ceux sans bilan cette semaine), produis 2 à 3 puces COURTES (une phrase chacune maximum) : les sujets les plus souvent abordés/contrôlés, et les résultats ou tendances notables. Si un animateur n'a aucun bilan, une seule puce suffit ("Aucun bilan cette semaine"). Reste factuel, base-toi uniquement sur les données fournies. Le tableau chiffré est déjà généré séparément, ne répète pas les chiffres bruts (nombre de bilans, de magasins) dans tes puces — concentre-toi sur le contenu qualitatif.

Réponds uniquement en JSON valide, sans texte avant/après, sans balises markdown, sous la forme :
{ "Nom Animateur 1": ["puce 1", "puce 2"], "Nom Animateur 2": ["puce 1", "puce 2"], ... }
Utilise exactement les noms d'animateurs tels que donnés en entrée, comme clés.`;

  let byArBullets = {};
  const debugInfo = { from, to, totalBilans: bilans.length, byAR: Object.fromEntries(Object.entries(byAR).map(([k,v]) => [k, v.length])) };

  if (bilans.length && env.ANTHROPIC_API_KEY) {
    const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2500, system: systemPrompt, messages: [{ role: 'user', content: sections }] }),
    });
    const claudeData = await claudeResp.json();
    if (claudeResp.ok) {
      const rawText = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
      try { byArBullets = JSON.parse(stripJsonFences(rawText)); }
      catch(e) { byArBullets = { 'Erreur': ['Réponse IA non-JSON : ' + rawText.slice(0, 300)] }; }
    } else {
      byArBullets = { 'Erreur': ['Erreur génération synthèse IA : ' + JSON.stringify(claudeData)] };
    }
  }

  const subject = `Bilan hebdomadaire réseau — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
  return { subject, from, to, byAR, byArBullets, debugInfo };
}

function formatHumeur(v) { return v === null || v === undefined ? '—' : v.toFixed(1); }
function formatDuree(v) { return v === null || v === undefined ? '—' : Math.round(v) + ' min'; }

async function sendWeeklyReport(env, override) {
  const { subject, byAR, byArBullets } = await generateWeeklyReport(env, override);
  const stores = await getMagasinsServerSide();

  // Version "tous magasins" pour Olivier : tableau récap par animateur + puces qualitatives
  const arStats = computeArStats(byAR);
  const olivierTable = htmlStatsTable(
    ['Animateur', 'Magasins visités', 'Bilans', 'Humeur moy.', 'Durée moy.'],
    arStats.map(s => [s.label, s.nbMagasins, s.nbBilans, formatHumeur(s.avgHumeur), formatDuree(s.avgDuree)])
  );
  const olivierBullets = htmlBulletSections(byArBullets);
  await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyHtml: wrapEmailBody(olivierTable + olivierBullets) });

  // Version par AR : tableau récap par magasin (les siens) + ses propres puces
  for (const [ar, bullets] of Object.entries(byArBullets)) {
    if (ar === 'Erreur') continue;
    const arEmail = getArEmail(stores, ar);
    if (!arEmail) continue;
    const arBilans = byAR[ar] || [];
    const storeStats = computeStoreStats(arBilans);
    const arTable = storeStats.length
      ? htmlStatsTable(['Magasin', 'Bilans', 'Dernière visite', 'Humeur moy.', 'Durée moy.'], storeStats.map(s => [s.label, s.nbBilans, s.lastDate || '—', formatHumeur(s.avgHumeur), formatDuree(s.avgDuree)]))
      : '';
    const arBulletsHtml = htmlBulletSections({ [ar]: bullets });
    try {
      await zimbraSendMail(env, { to: arEmail, subject: `Bilan hebdomadaire — ${ar}`, bodyHtml: wrapEmailBody(arTable + arBulletsHtml) });
    } catch(e) { console.error('Envoi bilan hebdo échoué pour', ar, e); }
  }
}

function stripJsonFences(text) {
  return text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
}

async function generateComHebdoCore(contentSource, framing, env) {
  if (!env.ANTHROPIC_API_KEY) throw new Error('Clé API Anthropic non configurée sur le Worker');

  const systemPrompt = `Tu aides à rédiger une communication hebdomadaire interne à partir des observations terrain (bilans de passage) de la semaine, ${framing}.

RÈGLES DE STYLE (à respecter strictement) :
- Ton motivant, jamais alarmiste.
- Ne JAMAIS pointer un magasin par son nom sur un point négatif — rester général ou parler de tendances plutôt que de nommer un magasin en difficulté.
- Convention interne : quand tu évoques le magasin de Montgeron, utilise le prénom "Eitan" (son manager) à la place du nom du magasin. Quand tu évoques Vitry, utilise "Dan". Pour tous les autres magasins, tu peux les citer par leur nom si c'est positif.
- Tu écris en français.

FORMATS ATTENDUS (réponds uniquement en JSON valide, sans texte avant/après, sans balises markdown) :
{
  "slack1": {"titre": "emoji + titre court", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "slack2": {"titre": "emoji + titre court (angle différent de slack1)", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "slack3": {"titre": "emoji + titre court (angle différent de slack1 et slack2)", "contenu": "2-4 phrases", "conclusion": "1 phrase percutante"},
  "message_general": "message autonome avec emojis, 4-8 phrases, ton motivant, à poster tel quel",
  "email_objet": "objet de l'email, sans emoji",
  "email_corps": "email narratif plus long (8-15 phrases), SANS AUCUN EMOJI (contrainte technique Zimbra), ton professionnel et motivant"
}

Les 3 messages Slack doivent couvrir des angles différents (ex: un fait marquant de la semaine, un point de vigilance sans nommer de magasin, un encouragement/objectif pour la semaine à venir) — évite les répétitions entre eux.`;

  const userPrompt = `Voici les observations terrain (bilans de passage) de la semaine :\n\n${contentSource}`;

  const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2500, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] }),
  });
  const claudeData = await claudeResp.json();
  if (!claudeResp.ok) throw new Error('Erreur API Claude : ' + JSON.stringify(claudeData));

  const rawText = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
  try {
    return JSON.parse(stripJsonFences(rawText));
  } catch (e) {
    throw new Error('Réponse IA non-JSON, impossible à parser : ' + rawText.slice(0, 300));
  }
}

async function generateComHebdo(env, override) {
  const { from, to, byAR } = await getWeekData(env, override);
  const sections = Object.entries(byAR)
    .filter(([, list]) => list.length)
    .map(([ar, list]) => `=== ${ar} (${list.length} bilan(s)) ===\n` + list.map(resumeBilan).join('\n\n---\n\n'))
    .join('\n\n\n');
  const contentSource = sections || '(Aucun bilan de passage enregistré cette semaine sur le réseau.)';
  const blocks = await generateComHebdoCore(contentSource, 'pour le directeur réseau qui communique sur l\'ensemble du réseau Optical Center', env);
  return { from, to, blocks };
}

async function generateComHebdoForAR(arName, arBilans, env) {
  const contentSource = arBilans.length
    ? arBilans.map(resumeBilan).join('\n\n---\n\n')
    : '(Aucun bilan de passage enregistré cette semaine pour ces magasins.)';
  const blocks = await generateComHebdoCore(contentSource, `pour l'animateur réseau ${arName} qui communique à son équipe sur ses propres magasins`, env);
  return blocks;
}

function formatComHebdoAsEmail(blocks) {
  return [
    `--- SLACK 1 ---`,
    `${blocks.slack1?.titre}\n${blocks.slack1?.contenu}\n${blocks.slack1?.conclusion}`,
    ``,
    `--- SLACK 2 ---`,
    `${blocks.slack2?.titre}\n${blocks.slack2?.contenu}\n${blocks.slack2?.conclusion}`,
    ``,
    `--- SLACK 3 ---`,
    `${blocks.slack3?.titre}\n${blocks.slack3?.contenu}\n${blocks.slack3?.conclusion}`,
    ``,
    `--- MESSAGE GÉNÉRAL ---`,
    blocks.message_general,
    ``,
    `--- EMAIL (objet: ${blocks.email_objet}) ---`,
    blocks.email_corps,
  ].join('\n');
}

async function sendComHebdo(env, override) {
  const { from, to, blocks } = await generateComHebdo(env, override);
  const subjectPrefix = `Com hebdo (brouillon) — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
  await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject: subjectPrefix + ' — réseau complet', bodyText: formatComHebdoAsEmail(blocks) });

  const { byAR } = await getWeekData(env, override || { from, to });
  const stores = await getMagasinsServerSide();
  for (const [ar, arBilans] of Object.entries(byAR)) {
    if (!arBilans.length) continue; // rien à communiquer pour cet AR cette semaine
    const arEmail = getArEmail(stores, ar);
    if (!arEmail) continue;
    try {
      const arBlocks = await generateComHebdoForAR(ar, arBilans, env);
      await zimbraSendMail(env, { to: arEmail, subject: subjectPrefix + ` — ${ar}`, bodyText: formatComHebdoAsEmail(arBlocks) });
    } catch(e) { console.error('Envoi com hebdo échoué pour', ar, e); }
  }
}

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Zimbra-Auth-Token, X-Notify-Token, X-Store-Token, X-AR-Session',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (request.method !== 'POST' && !(request.method === 'GET' && (url.pathname === '/bilans' || url.pathname === '/test-weekly-report' || url.pathname === '/com-hebdo' || url.pathname === '/test-com-hebdo'))) {
      return new Response('Méthode non autorisée', { status: 405, headers: corsHeaders });
    }

    try {
      if (url.pathname === '/upload') {
        const token = request.headers.get('X-Zimbra-Auth-Token');
        if (!token) {
          return new Response('Jeton manquant', { status: 400, headers: corsHeaders });
        }
        const contentType = request.headers.get('Content-Type') || '';
        const bodyBuffer = await request.arrayBuffer();
        const uploadRes = await fetch(ZIMBRA_UPLOAD_URL, {
          method: 'POST',
          headers: { 'Content-Type': contentType, 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: bodyBuffer,
        });
        const text = await uploadRes.text();
        return new Response(text, {
          status: uploadRes.status,
          headers: { 'Content-Type': 'text/plain', ...corsHeaders },
        });
      }

      if (url.pathname === '/notify') {
        // Vérification du token secret
        const notifyToken = request.headers.get('X-Notify-Token');
        if (notifyToken !== NOTIFY_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        const { to, subject, body, zimbraUser, zimbraPass } = await request.json();
        if (!to || !subject || !body || !zimbraUser || !zimbraPass) {
          return new Response('Paramètres manquants', { status: 400, headers: corsHeaders });
        }
        // Authentification Zimbra
        const authResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
            Body: {
              AuthRequest: {
                _jsns: 'urn:zimbraAccount',
                account: { by: 'name', _content: zimbraUser },
                password: { _content: zimbraPass }
              }
            }
          })
        });
        const authData = await authResp.json();
        const token = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!token) {
          return new Response('Auth Zimbra échouée', { status: 401, headers: corsHeaders });
        }
        // Envoi du mail de notification
        const sendResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: JSON.stringify({
            Header: {
              context: {
                _jsns: 'urn:zimbra',
                format: { _content: 'js', type: 'js' },
                authToken: [{ _content: token }]
              }
            },
            Body: {
              SendMsgRequest: {
                _jsns: 'urn:zimbraMail',
                m: {
                  su: { _content: subject },
                  e: [{ t: 't', a: to }],
                  mp: { ct: 'text/plain', content: { _content: body } }
                }
              }
            }
          })
        });
        const sendText = await sendResp.text();
        return new Response(sendText, {
          status: sendResp.status,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (url.pathname === '/ar-login') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);

        const { zimbraUser, zimbraPass } = await request.json();
        if (!zimbraUser || !zimbraPass) return jsonError('Identifiant et mot de passe requis', 400, corsHeaders);

        // Authentification réelle auprès de Zimbra (preuve de possession du compte)
        const authResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
            Body: {
              AuthRequest: {
                _jsns: 'urn:zimbraAccount',
                account: { by: 'name', _content: zimbraUser },
                password: { _content: zimbraPass }
              }
            }
          })
        });
        const authData = await authResp.json();
        const zimbraToken = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!zimbraToken) return jsonError('Identifiants Zimbra invalides', 401, corsHeaders);

        // Résolution serveur de l'identité AR à partir du référentiel magasins.csv
        // (jamais depuis des données envoyées par le téléphone)
        const localPart = zimbraUser.split('@')[0];
        const normalizedLogin = normalizeName(localPart);
        let ar = null;
        if (normalizedLogin.includes('baroukh')) {
          ar = 'ALL';
        } else {
          const stores = await getMagasinsServerSide();
          const uniqueARs = [...new Set(stores.map(s => s.animateur).filter(Boolean))];
          ar = uniqueARs.find(a => normalizeName(a) === normalizedLogin) || null;
        }
        if (!ar) {
          return jsonError("Identifiants valides mais aucun animateur ne correspond à '" + zimbraUser + "' dans le référentiel magasins. Vérifie l'orthographe du login vs le nom animateur dans magasins.csv.", 403, corsHeaders);
        }

        const sessionToken = await createArSession(ar);
        return new Response(JSON.stringify({ ok: true, sessionToken, ar, expiresInMs: AR_SESSION_TTL_MS }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/store-bilan') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        if (!env.DB) {
          return new Response('Base D1 non liée au Worker', { status: 500, headers: corsHeaders });
        }
        const data = await request.json();
        const magasinCode = data?.magasin?.code || null;
        const magasinLibelle = data?.magasin?.libelle || null;
        if (!magasinCode || !data?.date) {
          return new Response('Champs requis manquants (magasin.code, date)', { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          `INSERT INTO bilans (magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          magasinCode,
          magasinLibelle,
          data.ar || null,
          data.date,
          data.passage || null,
          data.humeur !== undefined && data.humeur !== '' ? parseInt(data.humeur) : null,
          data.ca_mensuel || null,
          data.ca_annuel || null,
          data.renta || null,
          JSON.stringify(data)
        ).run();
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/bilans') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);

        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);

        let allowedCodes = null;
        if (sessionAr !== 'ALL') {
          const stores = await getMagasinsServerSide();
          allowedCodes = stores.filter(s => s.animateur === sessionAr).map(s => s.code);
        }

        const magasinCode = url.searchParams.get('magasin_code');
        if (magasinCode && allowedCodes && !allowedCodes.includes(magasinCode)) {
          return jsonError('Accès non autorisé à ce magasin', 403, corsHeaders);
        }
        const from = url.searchParams.get('from');
        const to = url.searchParams.get('to');
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200'), 1000);

        let query = 'SELECT id, magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json, created_at FROM bilans WHERE 1=1';
        const binds = [];
        if (magasinCode) {
          query += ' AND magasin_code = ?'; binds.push(magasinCode);
        } else if (allowedCodes) {
          if (!allowedCodes.length) return new Response(JSON.stringify({ ok: true, results: [] }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
          query += ' AND magasin_code IN (' + allowedCodes.map(() => '?').join(',') + ')';
          binds.push(...allowedCodes);
        }
        if (from) { query += ' AND date >= ?'; binds.push(from); }
        if (to) { query += ' AND date <= ?'; binds.push(to); }
        query += ' ORDER BY date DESC LIMIT ?';
        binds.push(limit);

        const { results } = await env.DB.prepare(query).bind(...binds).all();
        return new Response(JSON.stringify({ ok: true, results }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/analyze') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response(JSON.stringify({ error: 'Non autorisé' }), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);
        if (!env.ANTHROPIC_API_KEY) {
          return new Response(JSON.stringify({ error: 'Clé API Anthropic non configurée sur le Worker (secret ANTHROPIC_API_KEY manquant ou non déployé)' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const { mode, bilans } = await request.json();
        if (!Array.isArray(bilans) || !bilans.length) {
          return new Response(JSON.stringify({ error: 'Aucune donnée à analyser' }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }

        let systemPrompt, userContent;
        if (mode === 'group') {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à préparer sa tournée terrain. On te donne l'historique récent de plusieurs magasins. Pour chaque magasin, produis une synthèse courte et actionnable : tendance générale, actions non résolues qui traînent, et 1 à 2 points de vigilance prioritaires. Reste factuel, base-toi uniquement sur les données fournies, sois concis (pas de blabla). Structure ta réponse par magasin avec un titre clair.`;
          userContent = bilans.map((storeBilans, i) =>
            `=== Magasin ${i + 1} ===\n` + storeBilans.map(resumeBilan).join('\n\n---\n\n')
          ).join('\n\n\n');
        } else {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à analyser l'historique d'un magasin. On te donne les bilans de passage successifs. Identifie les tendances (amélioration/dégradation), les actions récurrentes qui ne sont jamais résolues, et les points d'alerte. Reste factuel, base-toi uniquement sur les données fournies, sois concis et actionnable.`;
          userContent = bilans.map(resumeBilan).join('\n\n---\n\n');
        }

        const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model: 'claude-sonnet-5',
            max_tokens: 1500,
            system: systemPrompt,
            messages: [{ role: 'user', content: userContent }],
          }),
        });
        const claudeData = await claudeResp.json();
        if (!claudeResp.ok) {
          return new Response(JSON.stringify({ error: claudeData }), {
            status: claudeResp.status,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        const analysis = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
        return new Response(JSON.stringify({ ok: true, analysis }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/store-stats') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        try {
          const s = await request.json();
          if (!s.magasin) return jsonError('Champ magasin requis', 400, corsHeaders);
          await env.DB.prepare(
            `INSERT INTO store_stats (magasin, periode, date_extraction, ca_total, ca_opt, ca_audio, panier_moyen, taux_tc, taux_sop, taux_mdc, protheses_vendues, taux_essai, objectif, raf, prios_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            s.magasin, s.periode || null, s.dateExtraction || null,
            s.caTotal ?? null, s.caOpt ?? null, s.caAudio ?? null, s.panierMoyen ?? null,
            s.tauxTc ?? null, s.tauxSop ?? null, s.tauxMdc ?? null,
            s.prothesesVendues ?? null, s.tauxEssai ?? null, s.objectif ?? null, s.raf ?? null,
            JSON.stringify(s.prios || [])
          ).run();
          return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur enregistrement : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/store-observation') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        try {
          const o = await request.json();
          if (!o.m || !o.th || !o.tx || !o.t || !o.d) return jsonError('Champs requis manquants', 400, corsHeaders);
          await env.DB.prepare(
            `INSERT INTO observations (obs_id, magasin, theme, tone, texte, jour_label, date_key)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(o.id || null, o.m, o.th, o.t, o.tx, o.dl || null, o.d).run();
          return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur enregistrement : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/obs-generate') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        try {
          const { obs } = await request.json();
          const blocks = await generateObsComHebdo(obs, env);
          return new Response(JSON.stringify({ ok: true, blocks }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/obs-send') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        try {
          const fields = await request.json();
          if (!fields.slack1 && !fields.messageGeneral) return jsonError('Contenu manquant', 400, corsHeaders);
          const bodyText = formatObsEmail(fields);
          const subject = `Com hebdo — Montgeron / Vitry / Quincy / Fresnes`;
          await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText });
          await zimbraSendMail(env, { to: VANESSA_EMAIL, subject, bodyText });
          return new Response(JSON.stringify({ ok: true, sentTo: [OLIVIER_EMAIL, VANESSA_EMAIL] }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur envoi : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/com-hebdo') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);
        if (sessionAr !== 'ALL') return jsonError('Fonctionnalité réservée au profil réseau complet', 403, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        try {
          const { from, to, blocks } = await generateComHebdo(env);
          return new Response(JSON.stringify({ ok: true, from, to, blocks }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération com hebdo : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/test-com-hebdo') {
        const storeToken = request.headers.get('X-Store-Token') || url.searchParams.get('token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        const sendMode = url.searchParams.get('send'); // absent = prévisualisation, '1' = Olivier seul, 'all' = réseau + chaque AR
        const overrideFrom = url.searchParams.get('from');
        const overrideTo = url.searchParams.get('to');
        const override = (overrideFrom && overrideTo) ? { from: overrideFrom, to: overrideTo } : null;
        try {
          const { from, to, blocks } = await generateComHebdo(env, override);
          if (sendMode === 'all') {
            await sendComHebdo(env, override); // réseau complet + version par AR à chacun avec email configuré
          } else if (sendMode === '1') {
            const subject = `Com hebdo réseau (brouillon) — semaine du ${from.split('-').reverse().join('/')} au ${to.split('-').reverse().join('/')}`;
            await zimbraSendMail(env, { to: OLIVIER_EMAIL, subject, bodyText: formatComHebdoAsEmail(blocks) });
          }
          return new Response(JSON.stringify({ ok: true, sendMode: sendMode || 'preview', from, to, blocks }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération/envoi com hebdo : ' + String(e), 500, corsHeaders);
        }
      }

      if (url.pathname === '/test-weekly-report') {
        const storeToken = request.headers.get('X-Store-Token') || url.searchParams.get('token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);
        const sendEmail = url.searchParams.get('send') === '1'; // explicite : par défaut on ne fait que prévisualiser
        const overrideFrom = url.searchParams.get('from');
        const overrideTo = url.searchParams.get('to');
        const override = (overrideFrom && overrideTo) ? { from: overrideFrom, to: overrideTo } : null;
        try {
          const { subject, byAR, byArBullets, debugInfo } = await generateWeeklyReport(env, override);
          const arStats = computeArStats(byAR);
          let sentTo = [];
          if (sendEmail) {
            await sendWeeklyReport(env, override); // régénère et envoie réellement (Olivier + chaque AR avec email)
            sentTo = [OLIVIER_EMAIL];
          }
          return new Response(JSON.stringify({
            ok: true, emailSent: sendEmail, sentTo, subject, arStats, byArBullets, debugInfo
          }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        } catch (e) {
          return jsonError('Erreur génération/envoi du rapport : ' + String(e), 500, corsHeaders);
        }
      }

      // par défaut : relais SOAP (AuthRequest, SendMsgRequest, ...)
      const body = await request.text();
      const zimbraResponse = await fetch(ZIMBRA_SOAP_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const text = await zimbraResponse.text();
      return new Response(text, {
        status: zimbraResponse.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },

  async scheduled(event, env, ctx) {
    const cron = event.cron;
    if (cron === '0 14 * * SUN' || cron === '0 7 * * SUN') {
      ctx.waitUntil(sendComHebdo(env).catch(e => console.error('Erreur com hebdo:', e)));
    } else if (cron === '0 20 * * SUN' || cron === '0 22 * * SUN') {
      ctx.waitUntil(purgeWeeklySources(env).catch(e => console.error('Erreur purge hebdomadaire:', e)));
    } else if (cron === '0 6 * * SAT') {
      ctx.waitUntil(sendWeeklyReport(env).catch(e => console.error('Erreur rapport hebdomadaire:', e)));
    } else {
      console.error('Cron non reconnu, aucune action déclenchée:', cron);
    }
  }
};
