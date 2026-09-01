'use strict';

/*
 * Which vaults may be offered for sync-to-a-folder.
 *
 * Only a Standard vault can be synced over this path: its files are server-side encrypted, so the
 * SFTP endpoint can serve readable content. A zero-knowledge vault must NEVER be offered here —
 * routing its content through a server-decrypt sync would expose plaintext the server is never meant
 * to see. The tier is taken from the server's own vault metadata (authoritative), and the filter
 * FAILS CLOSED: only a vault the server explicitly marks Standard is eligible; anything zero-knowledge,
 * unknown, ambiguous, or missing a tier is excluded.
 */

// Read the server-authoritative tier from a vault record. The server names it `vault_type`; the
// reused UI also carries a normalized `type`. Accept either, but only a string tier counts.
function vaultTier(v) {
  const t = v && (v.vault_type != null ? v.vault_type : v.type);
  return typeof t === 'string' ? t : null;
}

// A vault is eligible only when the server explicitly marks it Standard.
function isStandardVault(v) {
  return vaultTier(v) === 'standard';
}

// Filter a raw vault list to the Standard-eligible set (fail-closed: zk/unknown/missing excluded).
function filterStandardVaults(list) {
  return (Array.isArray(list) ? list : []).filter(isStandardVault);
}

/**
 * Fetch the account's vaults from the server over the account session and return ONLY the
 * Standard-eligible ones, as { vaultId, vaultName }. The list is fetched here, in the main process,
 * from the server — never taken from the renderer or a client cache — so the tier that gates
 * eligibility is server-authoritative end to end. Fails closed: a non-OK response throws rather than
 * returning a partial or unverified list.
 * @param {object} o
 * @param {string} o.serverOrigin  the account server origin
 * @param {string} o.sessionToken  the account session bearer
 * @param {(url:string, init:object)=>Promise<{ok:boolean,status:number,json:()=>Promise<any>}>} fetchFn
 * @returns {Promise<{vaults:Array<{vaultId:string, vaultName:string}>, someExcluded:boolean}>}
 */
async function fetchStandardVaults({ serverOrigin, sessionToken }, fetchFn) {
  if (!serverOrigin || !sessionToken) throw new Error('the vault list needs a server origin and an account session');
  const url = `${String(serverOrigin).replace(/\/+$/, '')}/vaults`;
  const res = await fetchFn(url, { method: 'GET', headers: { Authorization: `Bearer ${sessionToken}` } });
  if (!res || !res.ok) throw new Error(`could not load the vault list (status ${res ? res.status : 'none'})`);
  const body = await res.json();
  const arr = Array.isArray(body) ? body : ((body && (body.vaults || body.data || body.items)) || []);
  // Filter on the RAW records (server tier), then expose only id + name for the picker.
  const vaults = filterStandardVaults(arr)
    .filter((v) => v && typeof v.id === 'string' && typeof v.name === 'string')
    .map((v) => ({ vaultId: v.id, vaultName: v.name }));
  // A BARE BOOLEAN only: whether the account has any vault that is not offer-eligible (zero-knowledge
  // or otherwise). It carries no count, and the excluded vaults' ids, names, and tier never leave the
  // main process — just enough for an honest "some vaults aren't shown here" note.
  const someExcluded = arr.length > vaults.length;
  return { vaults, someExcluded };
}

module.exports = { vaultTier, isStandardVault, filterStandardVaults, fetchStandardVaults };
