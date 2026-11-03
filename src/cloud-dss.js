const origin = 'https://dss.dtc.co.th';
const normalizeSim = value => String(value || '').replace(/\D/g, '').replace(/^66(?=[689]\d{8}$)/, '0');
const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
function failure(code) { const error = new Error(code); error.code = code; return error; }

export async function resolveCloudVehicle(env, request) {
  const sim = normalizeSim(request.sim);
  if (!/^0[689]\d{8}$/.test(sim)) throw failure('SIM_INVALID');
  if (env.DSS_RELAY_URL) {
    const relayUrl = new URL(env.DSS_RELAY_URL);
    if (relayUrl.protocol !== 'https:' || relayUrl.username || relayUrl.password || relayUrl.search || relayUrl.hash) throw failure('RELAY_URL_INVALID');
    const secret = String(env.DSS_RELAY_SHARED_SECRET || '');
    const privateJwk = String(env.DSS_RELAY_PRIVATE_JWK || '');
    if (!privateJwk && secret.length < 32) throw failure('RELAY_SECRET_NOT_CONFIGURED');
    for (let attempt = 0; attempt < 3; attempt++) {
    const raw = JSON.stringify({ timestamp: Math.floor(Date.now() / 1000), nonce: crypto.randomUUID(), request: { ...request, sim } });
    const key = privateJwk
      ? await crypto.subtle.importKey('jwk', JSON.parse(privateJwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      : await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signed = new Uint8Array(await crypto.subtle.sign(privateJwk ? { name: 'ECDSA', hash: 'SHA-256' } : 'HMAC', key, new TextEncoder().encode(raw)));
    let binary = ''; for (const byte of signed) binary += String.fromCharCode(byte);
    const signature = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    const response = await fetch(relayUrl, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json', 'x-service-signature': signature }, body: raw, signal: AbortSignal.timeout(150000) });
    if ([429, 502, 503, 504].includes(response.status) && attempt < 2) {
      await response.body?.cancel();
      // Retry only a real queued lookup after a free host's cold start/busy
      // response. No scheduled keepalive traffic is generated.
      await new Promise(resolve => setTimeout(resolve, (attempt + 1) * 10000));
      continue;
    }
    let data;
    try { data = await response.json(); } catch { throw failure('RELAY_INVALID_RESPONSE'); }
    if (!response.ok || !data.success) throw failure(data.code || 'RELAY_LOOKUP_FAILED');
    const vehicle = data.vehicle;
    if (!vehicle || normalizeSim(vehicle.sim) !== sim || !vehicle.customer || !vehicle.address || !vehicle.boxNo || !vehicle.plate) throw failure('RELAY_IDENTITY_INVALID');
    if (!Number.isFinite(Date.parse(vehicle.fetchedAt)) || Math.abs(Date.now() - Date.parse(vehicle.fetchedAt)) > 300000) throw failure('RELAY_DATA_EXPIRED');
    return vehicle;
    }
    throw failure('RELAY_UNAVAILABLE');
  }
  if (!env.DSS_USERNAME || !env.DSS_PASSWORD) throw failure('DSS_CLOUD_LOGIN_NOT_CONFIGURED');
  let session = '';
  async function call(path, fields) {
    let response;
    try { response = await fetch(origin + path, {
      method: fields ? 'POST' : 'GET', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'User-Agent': 'DTC-User-Tool/1.0', Referer: origin + '/dtcsys/index.php', Origin: origin,
        ...(session ? { Cookie: 'PHPSESSID=' + session } : {}) },
      ...(fields ? { body: new URLSearchParams(fields) } : {}), signal: AbortSignal.timeout(45000)
    }); } catch (cause) {
      const error = failure(cause.name === 'TimeoutError' || cause.message === 'DSS_TLS_TIMEOUT' ? 'DSS_NETWORK_TIMEOUT' : 'DSS_NETWORK_ERROR');
      error.stage = path.split('?')[0];
      error.transportCode = String(cause.cause?.code || cause.name || 'UNKNOWN');
      error.transportDetail = String(cause.message || cause.name || '').slice(0, 160);
      throw error;
    }
    const cookie = response.headers.get('set-cookie') || '';
    const match = cookie.match(/(?:^|[,\s])PHPSESSID=([^;,\s]+)/i);
    if (match) session = match[1];
    if (!response.ok) { const error = failure('DSS_HTTP_' + response.status); error.stage = path.split('?')[0]; throw error; }
    return response.text();
  }
  async function json(path, fields) {
    const text = await call(path, fields);
    try { return JSON.parse(text); } catch { throw failure('DSS_SESSION_EXPIRED'); }
  }
  await call('/dtcsys/index.php');
  const login = await json('/dtcsys/model/model_index.php?page=chkLogin', { inpID: env.DSS_USERNAME, inpPass: env.DSS_PASSWORD });
  if (String(login.check) !== '1' || !session) throw failure('DSS_LOGIN_FAILED');
  const erpSim = '66' + sim.slice(1);
  const redoc = await json('/dtcsys/model/REDOC/model_redoc_dlt_exportdlt.php?page=getInfoDlt', {
    flag_tab: '1', getSearchType: 'sim_no', getSearchText: erpSim, getSearchSDate: '', getSearchEDate: ''
  });
  const identities = (redoc.getDlt || []).filter(row => normalizeSim(row.equipmentcode || row.sim_no) === sim);
  if (!identities.length) throw failure('SIM_NOT_FOUND');
  const boxes = new Set(identities.map(row => clean(row.blackbox).toLowerCase()).filter(Boolean));
  const plates = new Set(identities.map(row => clean(row.truck).replace(/[\s-]/g, '')).filter(Boolean));
  if (boxes.size !== 1 || plates.size !== 1) throw failure('SIM_MATCH_AMBIGUOUS');
  const identity = identities.find(row => row.blackbox && row.truck);
  if (!identity) throw failure('VEHICLE_DATA_INCOMPLETE');
  const jobsResult = await json('/dtcsys/views/PLAN/model_jobtracking_main.php', {
    check: '1', limit: '10', page: '1', text_search: erpSim, type_search: 'sim'
  });
  const jobs = (jobsResult.getJobList || []).filter(row => normalizeSim(row.sim || row.job_sim) === sim);
  if (!jobs.length) throw failure('DSS_EXACT_JOB_NOT_FOUND');
  const job = jobs[0];
  if (job.blackbox && clean(job.blackbox).toLowerCase() !== clean(identity.blackbox).toLowerCase()) throw failure('DSS_IDENTITY_MISMATCH');
  if (job.truck_no && clean(job.truck_no).replace(/[\s-]/g, '') !== clean(identity.truck).replace(/[\s-]/g, '')) throw failure('DSS_IDENTITY_MISMATCH');
  if (!job.ref_doc_so) throw failure('DSS_SO_REQUIRED');
  const so = await json('/dtcsys/model/PLAN/model_plan_job_tracking.php?page=getSoDetail', { so: job.ref_doc_so });
  const header = so.getDlt_SO?.[0];
  if (!header) throw failure('DSS_SO_NOT_FOUND');
  const ship = Boolean(clean(header.ShipToDesc));
  const prefix = ship ? 'ship_to_' : 'sold_to_';
  const customer = clean(ship ? header.ShipToDesc : header.SoldToDesc);
  const address = [clean(header[prefix + 'address']),
    clean(header[prefix + 'district']) && 'แขวง/ตำบล' + clean(header[prefix + 'district']).replace(/^(แขวง|ตำบล)/, ''),
    clean(header[prefix + 'amphur']) && 'เขต/อำเภอ' + clean(header[prefix + 'amphur']).replace(/^(เขต|อำเภอ)/, ''),
    clean(header[prefix + 'province']) && 'จังหวัด' + clean(header[prefix + 'province']).replace(/^จังหวัด/, ''),
    clean(header[prefix + 'zipcode']) && 'รหัสไปรษณีย์ ' + clean(header[prefix + 'zipcode'])].filter(Boolean).join(' ');
  const phone = clean(header[prefix + 'telno']) ||
    clean(String(header.HeaderText || '').match(/โทร\.?\s*([0-9\-\s]{9,15})/)?.[1]) ||
    clean(String(job.job_detail || '').match(/โทร\s*[:：\-\=\s]\s*([0-9\-\s]{9,15})/)?.[1]) || clean(job.contact_customer_tel);
  const model = clean(request.model) || 'E-SERIES';
  if (!['E-SERIES', 'SWE', 'DTRACK', 'SWE-01', 'Smart Eye Plus'].includes(model)) throw failure('CERTIFICATE_MODEL_INVALID');
  if (!customer || !address || !clean(header[prefix + 'address'])) throw failure('CERTIFICATE_CUSTOMER_INCOMPLETE');
  return { customer, address, phone, plate: clean(identity.truck), sim, boxNo: clean(identity.blackbox), model,
    condition: request.condition || 'Good', source: 'DSS Live (Cloud login + exact SIM + Job/SO Ship To)', fetchedAt: new Date().toISOString() };
}
