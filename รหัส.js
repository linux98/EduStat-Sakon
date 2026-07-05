// ==========================================
// CODE.GS — EduData Sakon Enterprise v2.1
// Password: Plain Text + CacheService Layer
// ==========================================

const AGENCY_MAP = {
  "OBEC_1":"สพป.สกลนคร เขต 1","OBEC_2":"สพป.สกลนคร เขต 2","OBEC_3":"สพป.สกลนคร เขต 3",
  "OBEC_M":"สพม.สกลนคร","SPECIAL":"ศูนย์การศึกษาพิเศษสกลนคร","RATCHAPRACHA":"รร.ราชประชานุเคราะห์ 53",
  "OPEC":"สช. (เอกชน)","SNRU":"มรภ.สกลนคร","KU_CSC":"มก. ฉกส.","RMUTI_Sakon":"มทร.อีสาน สกลนคร",
  "WITEEDHAM":"รร.วิถีธรรม มรภ.สกลนคร","VEC":"อาชีวศึกษาสกลนคร","DOLE":"สกร. (ส่งเสริมการเรียนรู้)",
  "MUN_NAKHON":"เทศบาลนครสกลนคร","PAO_Sakon":"อบจ.สกลนคร","MUN_TAMBON":"เทศบาลตำบล",
  "NURSERY":"ศูนย์พัฒนาเด็กเล็ก/ศพด.","BPP":"ตชด.","BUDDHIST":"พระปริยัติธรรม","MSDHS":"พมจ.สกลนคร"
};
const GIS_COORDS = {
  "OBEC_1":{lat:17.1652,lng:104.1486},"OBEC_2":{lat:17.3321,lng:103.7745},
  "OBEC_3":{lat:17.6543,lng:103.5678},"OBEC_M":{lat:17.1701,lng:104.1402},
  "SPECIAL":{lat:17.1900,lng:104.1100},"RATCHAPRACHA":{lat:17.2000,lng:104.1200},
  "OPEC":{lat:17.1580,lng:104.1450},"SNRU":{lat:17.1850,lng:104.1000},
  "KU_CSC":{lat:17.1820,lng:104.0950},"RMUTI_Sakon":{lat:17.1800,lng:104.0900},
  "WITEEDHAM":{lat:17.1870,lng:104.1050},"VEC":{lat:17.1755,lng:104.1305},
  "DOLE":{lat:17.1550,lng:104.1350},"MUN_NAKHON":{lat:17.1620,lng:104.1500},
  "PAO_Sakon":{lat:17.1630,lng:104.1510},"MUN_TAMBON":{lat:17.1640,lng:104.1520},
  "NURSERY":{lat:17.1500,lng:104.1650},"BPP":{lat:17.1800,lng:104.1200},
  "BUDDHIST":{lat:17.1600,lng:104.1600},"MSDHS":{lat:17.1450,lng:104.1700}
};
const ROLE_SUPER  = 'super_admin';
const ROLE_ADMIN  = 'admin';
const ROLE_AGENCY = 'agency';
const IS_SUPER    = function(r){ return r === ROLE_SUPER; };
const IS_ADMIN_UP = function(r){ return r === ROLE_ADMIN || r === ROLE_SUPER; };
const IS_AGENCY_UP= function(r){ return r === ROLE_AGENCY || r === ROLE_ADMIN || r === ROLE_SUPER; };

// ─────────────────────────────────────────────
// CACHE LAYER — CacheService wrapper
// TTL สำหรับแต่ละประเภทข้อมูล:
//   Dashboard : 5 นาที  (ข้อมูลเปลี่ยนบ่อยพอสมควร)
//   Monitoring: 3 นาที  (ต้องการความสดใหม่มากกว่า)
//   FormTemplates: 10 นาที (เปลี่ยนน้อย)
//   Settings  : 15 นาที (เปลี่ยนไม่บ่อย)
//   GIS Coords: 30 นาที (แทบไม่เปลี่ยน)
// ─────────────────────────────────────────────
var CACHE_TTL = {
  DASHBOARD  : 300,   // 5 min
  MONITORING : 180,   // 3 min
  FORMS      : 600,   // 10 min
  SETTINGS   : 900,   // 15 min
  GIS        : 1800,  // 30 min
  USERS      : 60,    // 1 min (สั้นเพราะเกี่ยวกับ auth)
};

// ─────────────────────────────────────────────
// SECURITY LAYER: Password Hashing + Session Tokens
// ─────────────────────────────────────────────

// SHA-256 + random salt  →  "sha256:{salt}:{hex}"
function _hashPassword(plain, salt) {
  var bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, salt + '|' + plain, Utilities.Charset.UTF_8);
  return bytes.map(function(b){ return ('0'+(b&0xFF).toString(16)).slice(-2); }).join('');
}
function _encodePassword(plain) {
  var salt = Utilities.getUuid().replace(/-/g,'').substring(0,16);
  return 'sha256:' + salt + ':' + _hashPassword(plain, salt);
}
function _verifyPassword(plain, stored) {
  if (!stored) return false;
  if (stored.indexOf('sha256:') === 0) {
    var p = stored.split(':'); return p.length >= 3 && _hashPassword(plain, p[1]) === p[2];
  }
  return plain === stored; // legacy plain text — auto-migrated on next login
}

// Session Tokens — CacheService  key: 'sess_{uuid}'  TTL: 2h
function _createSession(userData) {
  var token = Utilities.getUuid();
  CacheService.getScriptCache().put('sess_' + token,
    JSON.stringify({ username:userData.username, role:userData.role,
                     agencyId:userData.agencyId, name:userData.name }), 7200);
  return token;
}
function _resolveSession(token) {
  if (!token || typeof token !== 'string' || token.length < 10) return null;
  try { var r = CacheService.getScriptCache().get('sess_'+token); return r ? JSON.parse(r) : null; }
  catch(e){ return null; }
}
function _invalidateSession(token) {
  if (token) CacheService.getScriptCache().remove('sess_'+token);
}

// Session Heartbeat — ต่ออายุ session อีก 2 ชั่วโมง (Renew TTL) เพื่อป้องกัน session หลุดกลางคัน
// เรียกจาก Frontend ทุก 25 นาที เมื่อ user ยังคงใช้งานระบบอยู่
function refreshSession(token) {
  if (!token || typeof token !== 'string' || token.length < 10) {
    return { success: false, message: 'token ไม่ถูกต้อง' };
  }
  try {
    var cache = CacheService.getScriptCache();
    var raw   = cache.get('sess_' + token);
    if (!raw) return { success: false, expired: true, message: 'เซสชันหมดอายุแล้ว กรุณาเข้าสู่ระบบใหม่' };
    // ต่ออายุอีก 2 ชั่วโมง (7200 วินาที)
    cache.put('sess_' + token, raw, 7200);
    return { success: true };
  } catch(e) {
    return { success: false, message: e.toString() };
  }
}

// Central auth resolver — sessionToken (trusted) > legacy userRole (deprecated)
// Returns { userRole, agencyId, username, name }  or  { error: {...} }
function _resolveAuth(payload) {
  if (!payload) return { error:{ success:false, message:'ไม่มีข้อมูล payload' } };
  if (payload.sessionToken) {
    var sess = _resolveSession(payload.sessionToken);
    if (!sess) return { error:{ success:false, message:'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่', sessionExpired:true } };
    return { userRole:sess.role, agencyId:sess.agencyId, username:sess.username, name:sess.name };
  }
  // Legacy fallback — client-provided (accepted until all clients updated)
  return { userRole:payload.userRole, agencyId:payload.agencyId||payload.userAgencyId };
}
// Overload สำหรับ function ที่รับ (userRole) แบบ positional
function _resolveAuthParam(payloadOrRole) {
  if (typeof payloadOrRole === 'object' && payloadOrRole !== null) return _resolveAuth(payloadOrRole);
  return { userRole: payloadOrRole };
}

// ─────────────────────────────────────────────
// CacheService.getScriptCache() — shared ทุก user, ทุก request
function _cacheGet(key) {
  try {
    var raw = CacheService.getScriptCache().get(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch(e) { return null; }
}

function _cacheSet(key, value, ttlSeconds) {
  try {
    var str = JSON.stringify(value);
    // CacheService จำกัด value ที่ 100KB ต่อ key
    if (str.length > 90000) {
      // ข้อมูลใหญ่เกิน → แบ่งเป็น chunks
      _cacheSetChunked(key, str, ttlSeconds);
      return;
    }
    CacheService.getScriptCache().put(key, str, ttlSeconds);
  } catch(e) {}
}

function _cacheSetChunked(key, str, ttlSeconds) {
  try {
    var chunkSize = 85000;
    var chunks    = Math.ceil(str.length / chunkSize);
    var cache     = CacheService.getScriptCache();
    var entries   = {};
    entries[key + '__meta'] = JSON.stringify({ chunks: chunks });
    for (var c = 0; c < chunks; c++) {
      entries[key + '__chunk_' + c] = str.slice(c * chunkSize, (c+1) * chunkSize);
    }
    cache.putAll(entries, ttlSeconds);
  } catch(e) {}
}

function _cacheGetChunked(key) {
  try {
    var cache = CacheService.getScriptCache();
    var meta  = cache.get(key + '__meta');
    if (!meta) return null;
    var chunks = JSON.parse(meta).chunks;
    var str    = '';
    for (var c = 0; c < chunks; c++) {
      var chunk = cache.get(key + '__chunk_' + c);
      if (!chunk) return null;
      str += chunk;
    }
    return JSON.parse(str);
  } catch(e) { return null; }
}

function _cacheGetSmart(key) {
  var direct = _cacheGet(key);
  if (direct !== null) return direct;
  return _cacheGetChunked(key);
}

// invalidate cache ทั้งหมด (เรียกหลัง write operations)
function _cacheInvalidate(keys) {
  try {
    var cache = CacheService.getScriptCache();
    cache.removeAll(keys);
  } catch(e) {}
}

// invalidate ทั้ง dashboard + monitoring เมื่อมีข้อมูลใหม่
function _invalidateDashboardCache() {
  var agKeys = ['OBEC_1','OBEC_2','OBEC_3','OBEC_M','VEC','OPEC','DLA','DOLE','BUDDHIST','BPP','SPECIAL','HIGHER','NURSERY'];
  // คำนวณปีปัจจุบัน ±2 ปี (พ.ศ.) เพื่อครอบคลุม key ที่อาจถูก cache ไว้
  var thisYear = new Date().getFullYear() + 543;
  var years = ['all', String(thisYear - 1), String(thisYear), String(thisYear + 1)];
  var keys = ['monitoring_all', 'yoy_data'];
  years.forEach(function(yr) {
    keys.push('dashboard_' + yr + '_all');
    agKeys.forEach(function(ag) {
      keys.push('dashboard_' + yr + '_' + ag);
    });
  });
  _cacheInvalidate(keys);
}

// ─────────────────────────────────────────────
// ROLE GUARDS
// ─────────────────────────────────────────────
function checkRole(callerRole, predicate, actionName) {
  if (!callerRole || typeof callerRole !== 'string') {
    logAction('UNKNOWN','SECURITY_DENY','ไม่มี role -> ' + actionName);
    return { allowed:false, error:{ success:false, message:'ไม่พบข้อมูลบทบาทผู้ใช้งาน กรุณาเข้าสู่ระบบใหม่' } };
  }
  if ([ROLE_SUPER,ROLE_ADMIN,ROLE_AGENCY].indexOf(callerRole) === -1) {
    logAction(callerRole,'SECURITY_DENY','role ไม่ถูกต้อง -> ' + actionName);
    return { allowed:false, error:{ success:false, message:'บทบาท "'+callerRole+'" ไม่ถูกต้องในระบบ' } };
  }
  if (!predicate(callerRole)) {
    logAction(callerRole,'SECURITY_DENY','สิทธิ์ไม่เพียงพอ -> ' + actionName);
    return { allowed:false, error:{ success:false, message:'บทบาท "'+callerRole+'" ไม่มีสิทธิ์ดำเนินการนี้' } };
  }
  return { allowed:true };
}

function checkAgencyOwnership(callerRole, callerAgencyId, targetAgencyId) {
  if (IS_ADMIN_UP(callerRole)) return { allowed:true };
  if (resolveAgencyId(callerAgencyId) !== resolveAgencyId(targetAgencyId)) {
    logAction(callerRole,'SECURITY_DENY',callerAgencyId+' พยายามส่งข้อมูลในนาม '+targetAgencyId);
    return { allowed:false, error:{ success:false, message:'ไม่สามารถส่งข้อมูลในนามสังกัดอื่นได้' } };
  }
  return { allowed:true };
}

// ─────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

function doGet(e) {
  try {
    if (e && e.parameter && e.parameter.page === 'reportbuilder') {
      var rbTmpl = HtmlService.createTemplateFromFile('ReportBuilder');
      rbTmpl.initToken = e.parameter.token || '';
      return rbTmpl.evaluate()
        .setTitle('Report Builder — EduData Sakon')
        .addMetaTag('viewport','width=device-width,initial-scale=1')
        .setSandboxMode(HtmlService.SandboxMode.IFRAME)
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
    }
    return HtmlService.createTemplateFromFile('Index').evaluate()
      .setTitle('EduData Sakon - Enterprise v2.1')
      .addMetaTag('viewport','width=device-width,initial-scale=1')
      .setSandboxMode(HtmlService.SandboxMode.IFRAME)
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  } catch(e) {
    return HtmlService.createHtmlOutput('<h2>'+e.toString()+'</h2>');
  }
}


function setup() {
  initSetup();
  seedOBECMTemplates();
}
function getReportBuilderUrl() { return ScriptApp.getService().getUrl()+'?page=reportbuilder'; }
function getAgencyMasterList() { return AGENCY_MAP; }

function resolveAgencyId(raw) {
  if (!raw) return raw;
  if (AGENCY_MAP[raw]) return raw;
  return Object.keys(AGENCY_MAP).filter(function(k){ return AGENCY_MAP[k]===raw; })[0] || raw;
}

function logAction(userRole, action, details) {
  try {
    var s = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AuditLogs');
    if (s) s.appendRow([Utilities.formatDate(new Date(),"Asia/Bangkok","dd/MM/yyyy HH:mm:ss"), userRole||'UNKNOWN', action, details]);
  } catch(e) {}
}

// ─────────────────────────────────────────────
// 1. INIT SETUP
// ─────────────────────────────────────────────
function initSetup() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var dS = ss.getSheetByName('Data');
  if (!dS) dS = ss.insertSheet('Data');
  var cH = ['ID','Timestamp','AgencyID','FormID','ReportTitle','Status','Lat','Lng','RawDataJSON','AdminComment'];
  var fR = dS.getRange(1,1,1,cH.length).getValues()[0], nF = false;
  for (var hi=0;hi<cH.length;hi++) { if (String(fR[hi]||'')!==cH[hi]) { nF=true; break; } }
  if (nF) { dS.getRange(1,1,1,cH.length).setValues([cH]).setFontWeight('bold').setBackground('#f1f3f4'); dS.setFrozenRows(1); }

  var fT = ss.getSheetByName('FormTemplates');
  if (!fT) fT = ss.insertSheet('FormTemplates');
  var fC = ['FormID','FormName','AgencyID','FormJSON','Deadline'];
  var fF = fT.getRange(1,1,1,fC.length).getValues()[0], fN = false;
  for (var fhi=0;fhi<fC.length;fhi++) { if (String(fF[fhi]||'')!==fC[fhi]) { fN=true; break; } }
  if (fN) { fT.getRange(1,1,1,fC.length).setValues([fC]).setFontWeight('bold').setBackground('#f1f3f4'); fT.setFrozenRows(1); }

  if (!ss.getSheetByName('AuditLogs')) {
    var s3 = ss.insertSheet('AuditLogs');
    s3.appendRow(['Timestamp','UserRole','Action','Details']);
    s3.getRange('A1:D1').setFontWeight('bold').setBackground('#fce8e6'); s3.setFrozenRows(1);
  }
  if (!ss.getSheetByName('Users')) {
    var s4 = ss.insertSheet('Users');
    s4.appendRow(['Username','Password','Role','Name','AgencyID','Status','Email']);
    s4.getRange('A1:G1').setFontWeight('bold').setBackground('#d2e3fc'); s4.setFrozenRows(1);
    var du = [
      ['super','1234',ROLE_SUPER,'ผู้อำนวยการเขต','ALL','Active',''],
      ['admin','1234',ROLE_ADMIN,'ผู้ดูแลระบบส่วนกลาง','ALL','Active',''],
      ['obec1','1234',ROLE_AGENCY,'จนท. สพป.สกลนคร เขต 1','OBEC_1','Active',''],
      ['obec2','1234',ROLE_AGENCY,'จนท. สพป.สกลนคร เขต 2','OBEC_2','Active',''],
      ['obec3','1234',ROLE_AGENCY,'จนท. สพป.สกลนคร เขต 3','OBEC_3','Active',''],
      ['obecm','1234',ROLE_AGENCY,'จนท. สพม.สกลนคร','OBEC_M','Active',''],
      ['special','1234',ROLE_AGENCY,'จนท. ศูนย์การศึกษาพิเศษสกลนคร','SPECIAL','Active',''],
      ['ratchapracha','1234',ROLE_AGENCY,'จนท. รร.ราชประชานุเคราะห์ 53','RATCHAPRACHA','Active',''],
      ['opec','1234',ROLE_AGENCY,'จนท. สช. (เอกชน)','OPEC','Active',''],
      ['snru','1234',ROLE_AGENCY,'จนท. มรภ.สกลนคร','SNRU','Active',''],
      ['kucsc','1234',ROLE_AGENCY,'จนท. มก. ฉกส.','KU_CSC','Active',''],
      ['rmutisk','1234',ROLE_AGENCY,'จนท. มทร.อีสาน สกลนคร','RMUTI_Sakon','Active',''],
      ['witeedham','1234',ROLE_AGENCY,'จนท. รร.วิถีธรรม มรภ.สกลนคร','WITEEDHAM','Active',''],
      ['vec','1234',ROLE_AGENCY,'จนท. อาชีวศึกษา','VEC','Active',''],
      ['dole','1234',ROLE_AGENCY,'จนท. สกร.','DOLE','Active',''],
      ['munnakhon','1234',ROLE_AGENCY,'จนท. เทศบาลนครสกลนคร','MUN_NAKHON','Active',''],
      ['paosakon','1234',ROLE_AGENCY,'จนท. อบจ.สกลนคร','PAO_Sakon','Active',''],
      ['muntambon','1234',ROLE_AGENCY,'จนท. เทศบาลตำบล','MUN_TAMBON','Active',''],
      ['nursery','1234',ROLE_AGENCY,'จนท. ศูนย์พัฒนาเด็กเล็ก/ศพด.','NURSERY','Active',''],
      ['bpp','1234',ROLE_AGENCY,'จนท. ตชด.','BPP','Active',''],
      ['buddhist','1234',ROLE_AGENCY,'จนท. พระปริยัติธรรม','BUDDHIST','Active',''],
      ['msdhs','1234',ROLE_AGENCY,'จนท. พมจ.สกลนคร','MSDHS','Active','']
    ];
    s4.getRange(2,1,du.length,7).setValues(du);
  }

  if (!ss.getSheetByName('Settings')) {
    var s5 = ss.insertSheet('Settings');
    s5.appendRow(['Key','Value']); s5.getRange('A1:B1').setFontWeight('bold').setBackground('#e6f4ea'); s5.setFrozenRows(1);
    s5.appendRow(['system_open','true']); s5.appendRow(['academic_year',new Date().getFullYear()+543]); s5.appendRow(['system_version','2.1']);
  }

  if (!ss.getSheetByName('Issues')) {
    var sIssues = ss.insertSheet('Issues');
    sIssues.appendRow(['Timestamp', 'ReporterName', 'Agency', 'Contact', 'Detail', 'Status', 'ResolveComment']);
    sIssues.getRange('A1:G1').setFontWeight('bold').setBackground('#fce8e6'); sIssues.setFrozenRows(1);
  }
}

/**
 * ฟังก์ชันสำหรับผู้ดูแลระบบรันผ่าน Script Editor เพื่ออัปเดตบัญชีผู้ใช้ 20 หน่วยงานทันที
 */
function forceResetUsersSheet() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (sheet) {
    try {
      ss.deleteSheet(sheet);
    } catch(e) {
      sheet.clear();
    }
  }
  initSetup();
  Logger.log("✅ รีเซ็ตตาราง Users และสร้างบัญชีผู้ใช้งาน 20 สังกัดใหม่ใน Google Sheets เรียบร้อยแล้ว!");
}

// ─────────────────────────────────────────────
// 2. AUTHENTICATE — Rate Limit + Hash + Session
// ─────────────────────────────────────────────
function authenticateUser(payload) {
  try {
    initSetup();
    var user    = payload.username.toLowerCase().trim();
    var pass    = payload.password.trim();
    var failKey = 'loginfail_' + user;
    var cache   = CacheService.getScriptCache();

    // Rate limit: ล็อก 15 นาที หลัง fail 5 ครั้ง
    var fails = parseInt(cache.get(failKey) || '0');
    if (fails >= 5) {
      logAction('UNKNOWN', 'LOGIN_LOCKED', 'ล็อกชั่วคราว: ' + user);
      return { success:false, message:'บัญชีถูกล็อกชั่วคราว กรุณารอ 15 นาทีแล้วลองใหม่' };
    }

    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet.getDataRange().getValues();

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]||'').toLowerCase().trim() !== user) continue;

      // ตรวจรหัสผ่าน (รองรับทั้ง hash และ plain text legacy)
      var stored = String(data[i][1]||'').trim();
      if (!_verifyPassword(pass, stored)) {
        cache.put(failKey, String(fails + 1), 900);
        logAction('UNKNOWN', 'LOGIN_FAILED', 'user:' + user + ' (ครั้งที่ ' + (fails+1) + ')');
        var warn = fails >= 3 ? ' (เหลืออีก ' + (5-fails-1) + ' ครั้งก่อนถูกล็อก)' : '';
        return { success:false, message:'ชื่อผู้ใช้งานหรือรหัสผ่านไม่ถูกต้อง' + warn };
      }

      // บัญชีถูกระงับ
      if (data[i][5] !== 'Active') {
        logAction(data[i][2], 'LOGIN_DENIED', 'บัญชีถูกระงับ: ' + user);
        return { success:false, message:'บัญชีนี้ถูกระงับการใช้งาน โปรดติดต่อ Admin' };
      }

      // Auto-migrate: plain text → hash เมื่อ login สำเร็จครั้งแรก
      if (stored.indexOf('sha256:') !== 0) {
        sheet.getRange(i+1, 2).setValue(_encodePassword(pass));
        _cacheInvalidate(['users_list']);
      }

      // ล้าง fail counter + สร้าง session token
      cache.remove(failKey);
      var agId     = data[i][4];
      var userData = { username:data[i][0], role:data[i][2], name:data[i][3],
                       agencyId:agId, agency:AGENCY_MAP[agId]||agId };
      var token    = _createSession(userData);
      logAction(data[i][2], 'LOGIN', 'user:'+userData.username+' | name:'+userData.name+' | agency:'+agId);
      return { success:true, message:'เข้าสู่ระบบสำเร็จ', sessionToken:token, userData:userData };
    }

    // ไม่พบ username
    cache.put(failKey, String(fails + 1), 900);
    logAction('UNKNOWN', 'LOGIN_FAILED', 'user:' + user + ' ไม่พบ');
    return { success:false, message:'ชื่อผู้ใช้งานหรือรหัสผ่านไม่ถูกต้อง' };
  } catch(e) { return { success:false, message:'เกิดข้อผิดพลาด: ' + e.toString() }; }
}

function logoutUser(sessionToken) {
  _invalidateSession(sessionToken);
  return { success:true };
}

// ─────────────────────────────────────────────
// 3. SETTINGS — cache 15 นาที
// ─────────────────────────────────────────────
function getSettings() {
  var CACHE_KEY = 'settings_all';
  var cached = _cacheGet(CACHE_KEY);
  if (cached) return cached;

  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Settings');
  if (!sheet) return {};
  var data = sheet.getDataRange().getValues(), obj = {};
  for (var i=1;i<data.length;i++) { if (data[i][0]) obj[data[i][0]] = data[i][1]; }

  _cacheSet(CACHE_KEY, obj, CACHE_TTL.SETTINGS);
  return obj;
}

function saveSetting(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_SUPER, 'saveSetting');
  if (!g.allowed) return g.error;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Settings');
    if (!sheet) return { success:false, message:'ไม่พบ Settings sheet' };
    var data = sheet.getDataRange().getValues();
    var found = false;
    for (var i=1;i<data.length;i++) {
      if (data[i][0]===payload.key) { sheet.getRange(i+1,2).setValue(payload.value); found=true; break; }
    }
    if (!found) sheet.appendRow([payload.key, payload.value]);
    logAction(payload.userRole,'Save Setting',payload.key+' = '+payload.value);
    _cacheInvalidate(['settings_all']); // invalidate cache ทันที
    return { success:true, message:'บันทึกการตั้งค่าเรียบร้อยแล้ว' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

// ─────────────────────────────────────────────
// 4. USER MANAGEMENT — cache 1 นาที (list เท่านั้น)
// ─────────────────────────────────────────────
function getUsersList(payloadOrRole) {
  var auth = _resolveAuthParam(payloadOrRole); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getUsersList');
  if (!g.allowed) return g.error;

  var CACHE_KEY = 'users_list';
  var cached = _cacheGet(CACHE_KEY);
  if (cached) return cached;

  initSetup();
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
  var data  = sheet.getDataRange().getDisplayValues();
  var result = [];
  for (var i=1;i<data.length;i++) {
    if (!data[i][0]) continue;
    result.push({ username:data[i][0], role:data[i][2], name:data[i][3],
      agencyId:data[i][4], agency:AGENCY_MAP[data[i][4]]||data[i][4], status:data[i][5], email:data[i][6]||'' });
  }
  _cacheSet(CACHE_KEY, result, CACHE_TTL.USERS);
  return result;
}

function saveUser(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'saveUser');
  if (!g.allowed) return g.error;
  if (payload.role===ROLE_SUPER) return { success:false, message:'ไม่สามารถสร้างบัญชี Super Admin ผ่านระบบนี้ได้' };
  try {
    initSetup();
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet.getDataRange().getValues();
    var uname = payload.username.toLowerCase().trim();
    if (!payload.isEdit) {
      for (var i=1;i<data.length;i++) { if (String(data[i][0]).toLowerCase()===uname) return { success:false, message:'ชื่อผู้ใช้ "'+uname+'" มีอยู่แล้ว' }; }
    }
    var agId  = resolveAgencyId(payload.agencyId||'ALL');
    var pp    = payload.password ? _encodePassword(payload.password.trim()) : null;
    var email = payload.email ? payload.email.trim() : '';
    var nr    = [uname, pp, payload.role||ROLE_AGENCY, payload.name||'', agId, payload.status||'Active', email];
    if (payload.isEdit) {
      for (var j=1;j<data.length;j++) {
        if (String(data[j][0]).toLowerCase()===uname) {
          sheet.getRange(j+1,3).setValue(nr[2]); sheet.getRange(j+1,4).setValue(nr[3]);
          sheet.getRange(j+1,5).setValue(nr[4]); sheet.getRange(j+1,6).setValue(nr[5]);
          sheet.getRange(j+1,7).setValue(nr[6]);
          if (pp) sheet.getRange(j+1,2).setValue(pp);
          logAction(auth.userRole,'Update User','แก้ไขบัญชี: '+uname);
          _cacheInvalidate(['users_list']);
          return { success:true, message:'แก้ไขข้อมูลบัญชี "'+uname+'" เรียบร้อยแล้ว' };
        }
      }
      return { success:false, message:'ไม่พบบัญชีที่ต้องการแก้ไข' };
    } else {
      if (!payload.password || payload.password.trim().length < 8) return { success:false, message:'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร' };
      sheet.appendRow(nr);
      logAction(auth.userRole,'Create User','สร้างบัญชีใหม่: '+uname+' ('+nr[2]+')');
      _cacheInvalidate(['users_list']);
      return { success:true, message:'สร้างบัญชี "'+uname+'" เรียบร้อยแล้ว' };
    }
  } catch(e) { return { success:false, message:e.toString() }; }
}

function deleteUser(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'deleteUser');
  if (!g.allowed) return g.error;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet.getDataRange().getValues();
    var uname = payload.username.toLowerCase().trim();
    if (uname==='super') return { success:false, message:'ไม่สามารถลบบัญชี Super Admin หลักได้' };
    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]).toLowerCase()===uname) {
        sheet.deleteRow(i+1); logAction(payload.userRole,'Delete User','ลบบัญชี: '+uname);
        _cacheInvalidate(['users_list']);
        return { success:true, message:'ลบบัญชี "'+uname+'" เรียบร้อยแล้ว' };
      }
    }
    return { success:false, message:'ไม่พบบัญชีที่ต้องการลบ' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

function resetPassword(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'resetPassword');
  if (!g.allowed) return g.error;
  if (!payload.newPassword||payload.newPassword.trim().length<8) return { success:false, message:'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร' };
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet.getDataRange().getValues();
    var uname = payload.username.toLowerCase().trim();
    var np    = _encodePassword(payload.newPassword.trim());
    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]).toLowerCase()===uname) {
        sheet.getRange(i+1,2).setValue(np);
        logAction(auth.userRole,'Reset Password','รีเซ็ตรหัสผ่าน: '+uname);
        _cacheInvalidate(['users_list']);
        return { success:true, message:'รีเซ็ตรหัสผ่านของ "'+uname+'" เรียบร้อยแล้ว' };
      }
    }
    return { success:false, message:'ไม่พบบัญชีที่ต้องการรีเซ็ต' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

function toggleUserStatus(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'toggleUserStatus');
  if (!g.allowed) return g.error;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet.getDataRange().getValues();
    var uname = payload.username.toLowerCase().trim();
    if (uname==='super') return { success:false, message:'ไม่สามารถระงับบัญชี Super Admin หลักได้' };
    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]).toLowerCase()===uname) {
        var ns = data[i][5]==='Active'?'Inactive':'Active';
        sheet.getRange(i+1,6).setValue(ns);
        logAction(auth.userRole,'Toggle User',(ns==='Active'?'เปิด':'ระงับ')+'บัญชี: '+uname);
        _cacheInvalidate(['users_list']);
        return { success:true, message:(ns==='Active'?'เปิดใช้งาน':'ระงับ')+'บัญชี "'+uname+'" เรียบร้อยแล้ว', newStatus:ns };
      }
    }
    return { success:false, message:'ไม่พบบัญชี' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

// ─────────────────────────────────────────────
// 5. FORM TEMPLATES — cache 10 นาที
// ─────────────────────────────────────────────
function getAllFormTemplates(payloadOrRole) {
  var auth = _resolveAuthParam(payloadOrRole);
  if (auth.error) return auth.error;
  if (!IS_ADMIN_UP(auth.userRole)) return [];

  var CACHE_KEY = 'forms_all';
  var cached = _cacheGetSmart(CACHE_KEY);
  if (cached) return cached;

  initSetup();
  var sheet  = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('FormTemplates');
  var data   = sheet.getDataRange().getValues();
  var result = [];
  for (var i=1;i<data.length;i++) {
    if (!data[i][0]) continue;
    var fc = []; try { fc = JSON.parse(data[i][3]); } catch(e) {}
    result.push({ formId:data[i][0], formName:data[i][1], agencyId:data[i][2],
      fieldCount:fc.length, formConfig:fc, deadline:data[i][4]?String(data[i][4]):'' });
  }
  _cacheSet(CACHE_KEY, result, CACHE_TTL.FORMS);
  return result;
}

function getAvailableFormsForAgency(agencyId) {
  var id   = String(agencyId||'ALL');
  var CACHE_KEY = 'forms_agency_' + id.replace(/,/g,'_');
  var cached = _cacheGetSmart(CACHE_KEY);
  if (cached) return cached;

  var ids = id.split(',').map(function(s){ return s.trim(); }).filter(Boolean);
  initSetup();
  var sheet  = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('FormTemplates');
  var data   = sheet.getDataRange().getValues();
  var headers = data[0];
  var isMultiRowColIdx = headers.indexOf('IsMultiRow');
  var result = [], seen = {};
  for (var i=1;i<data.length;i++) {
    if (!data[i][0]||seen[data[i][0]]) continue;
    var fAg  = String(data[i][2]);
    var fIds = fAg.split(',').map(function(s){ return s.trim(); });
    var match = fIds.indexOf('ALL')>=0;
    if (!match) { for (var j=0;j<ids.length;j++) { if (ids[j]==='ALL'||fIds.indexOf(ids[j])>=0) { match=true; break; } } }
    if (!match) continue;
    seen[data[i][0]] = true;
    var fc=[]; try { fc=JSON.parse(data[i][3]); } catch(e) {}
    var isMulti = false;
    if (isMultiRowColIdx !== -1 && data[i][isMultiRowColIdx] !== undefined) {
      var cellVal = data[i][isMultiRowColIdx];
      isMulti = cellVal === true || String(cellVal) === '1' || String(cellVal) === 'true';
    }
    result.push({ formId:String(data[i][0]), formName:String(data[i][1]), agencyId:fAg, fieldCount:fc.length, formConfig:fc, isMultiRow:isMulti });
  }
  _cacheSet(CACHE_KEY, result, CACHE_TTL.FORMS);
  return result;
}

function _invalidateFormsCache() {
  // invalidate forms cache ทั้งหมด
  var keys = ['forms_all'];
  Object.keys(AGENCY_MAP).forEach(function(k){ keys.push('forms_agency_'+k); });
  keys.push('forms_agency_ALL');
  _cacheInvalidate(keys);
}

function saveFormTemplate(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'saveFormTemplate');
  if (!g.allowed) return g.error;
  try {
    initSetup();
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('FormTemplates');
    var data  = sheet.getDataRange().getValues();
    var formId = payload.formId, formName = payload.formName;
    var agencyId = resolveAgencyId(payload.agencyId)||'ALL';
    var deadline = payload.deadline||'';
    var fcJSON   = JSON.stringify(payload.formConfig);
    var updated  = false;
    for (var i=1;i<data.length;i++) {
      if (data[i][0]===formId) {
        sheet.getRange(i+1,2).setValue(formName); sheet.getRange(i+1,3).setValue(agencyId);
        sheet.getRange(i+1,4).setValue(fcJSON);   sheet.getRange(i+1,5).setValue(deadline);
        updated=true; break;
      }
    }
    if (!updated) sheet.appendRow([formId,formName,agencyId,fcJSON,deadline]);
    logAction(auth.userRole,'Save Form','บันทึกแบบฟอร์ม: '+formName);
    _invalidateFormsCache(); // invalidate forms cache
    return { success:true, message:'บันทึกแบบฟอร์ม "'+formName+'" เรียบร้อยแล้ว' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

function deleteFormTemplate(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'deleteFormTemplate');
  if (!g.allowed) return g.error;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('FormTemplates');
    var data  = sheet.getDataRange().getValues();
    for (var i=1;i<data.length;i++) {
      if (data[i][0]===payload.formId) {
        sheet.deleteRow(i+1); logAction(auth.userRole,'Delete Form','ลบแบบฟอร์ม ID: '+payload.formId);
        _invalidateFormsCache();
        return { success:true, message:'ลบแบบฟอร์มเรียบร้อยแล้ว' };
      }
    }
    return { success:false, message:'ไม่พบแบบฟอร์มที่ต้องการลบ' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

function duplicateFormTemplate(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'duplicateFormTemplate');
  if (!g.allowed) return g.error;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('FormTemplates');
    var data  = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === payload.formId) {
        var newId   = 'form_' + Date.now().toString(36);
        var newName = (data[i][1] || '') + ' (สำเนา)';
        sheet.appendRow([newId, newName, data[i][2], data[i][3], data[i][4]]);
        _invalidateFormsCache();
        logAction(auth.userRole, 'Duplicate Form', 'คัดลอก: ' + data[i][1]);
        return { success: true, message: 'คัดลอกแบบฟอร์มเป็น "' + newName + '" เรียบร้อยแล้ว' };
      }
    }
    return { success: false, message: 'ไม่พบแบบฟอร์มต้นฉบับ' };
  } catch(e) { return { success: false, message: e.toString() }; }
}

/**
 * ─────────────────────────────────────────────
 * UPDATE STATUS: อนุมัติ หรือ ตีกลับ (Admin)
 * ─────────────────────────────────────────────
 */
function updateDataStatus(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'updateDataStatus');
  if (!g.allowed) return g.error;
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Data');
    if (!sheet) {
      return { success: false, message: 'ไม่พบแผ่นงาน (Data)' };
    }

    var data = sheet.getDataRange().getValues();
    var rowIndex = -1;
    
    // ค้นหา ID ที่ต้องการอัปเดต
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === String(payload.id).trim()) {
        rowIndex = i + 1;
        break;
      }
    }

    if (rowIndex === -1) {
      return { success: false, message: 'ไม่พบรหัสข้อมูล: ' + payload.id };
    }

    // 🛡️ ป้องกัน Error: ตรวจสอบว่าแผ่นงานมีถึงคอลัมน์ J (10) หรือไม่ ถ้าไม่มีให้สร้างเพิ่มอัตโนมัติ
    if (sheet.getMaxColumns() < 10) {
      sheet.insertColumnsAfter(sheet.getMaxColumns(), 10 - sheet.getMaxColumns());
      sheet.getRange(1, 10).setValue('AdminComment');
      sheet.getRange(1, 10).setFontWeight('bold').setBackground('#f1f3f4');
    }

    // คอลัมน์ F (6) คือ Status | คอลัมน์ J (10) คือ AdminComment
    sheet.getRange(rowIndex, 6).setValue(payload.status);
    sheet.getRange(rowIndex, 10).setValue(payload.comment || '');
    logAction(auth.userRole, 'Update Status', 'ID:' + payload.id + ' → ' + payload.status);

    // ล้าง Cache ทั้ง monitoring และ dashboard
    _invalidateDashboardCache();
    return { success: true, message: 'อัปเดตสถานะเป็น "' + payload.status + '" สำเร็จ' };

  } catch (e) {
    // 🎯 โยนข้อความ Error ที่แท้จริงกลับไปที่หน้าเว็บ จะได้รู้ว่าพังที่ไหน
    return { success: false, message: 'ข้อผิดพลาด Server: ' + e.message };
  }
}

/**
 * ─────────────────────────────────────────────
 * SUBMIT DATA: บันทึกข้อมูลใหม่ และ การส่งแก้ไข (Resubmit)
 * ─────────────────────────────────────────────
 */
function submitData(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var roleCheck = checkRole(auth.userRole, IS_AGENCY_UP, 'submitData');
  if (!roleCheck.allowed) return roleCheck.error;
  var callerAgency = auth.agencyId || payload.userAgencyId || payload.agencyId;
  var ownerCheck = checkAgencyOwnership(auth.userRole, callerAgency, payload.agencyId);
  if (!ownerCheck.allowed) return ownerCheck.error;

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Data');
  if (!sheet) {
    return { success: false, message: 'ไม่พบแผ่นงาน (Data)' };
  }

  if (!payload.formData || typeof payload.formData !== 'object') {
    return { success: false, message: 'ข้อมูลแบบฟอร์มไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง' };
  }

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000); // รอสิทธิ์เข้าเขียนข้อมูลสูงสุด 30 วินาที
  } catch (e) {
    return { success: false, message: 'ระบบหนาแน่นชั่วคราว (Lock timeout) กรุณากดส่งใหม่อีกครั้งใน 10 วินาที' };
  }

  try {
    var data = sheet.getDataRange().getValues();
    var timestamp = new Date();
    var existingRowIndex = -1;

    if (payload.id) {
      for (var i = 1; i < data.length; i++) {
        // เปรียบเทียบ ID คอลัมน์ A แบบ String
        if (String(data[i][0]).trim() === String(payload.id).trim()) {
          existingRowIndex = i + 1;
          break;
        }
      }
    }

    // 🎯 จัดเรียงคอลัมน์ให้ตรงกับแผ่นงาน Data ของคุณ (A ถึง J)
    var rowData = [
      payload.id || "RPT_" + new Date().getTime(), // A: ID
      Utilities.formatDate(timestamp, "GMT+7", "dd/MM/yyyy HH:mm:ss"), // B: Timestamp
      payload.agencyId, // C: AgencyID
      payload.formId, // D: FormID
      payload.formData.report_title || "-", // E: ReportTitle
      'รออนุมัติ', // F: Status (รอตรวจสอบและอนุมัติจาก Admin)
      '', // G: Lat (ถ้ามีค่อยดึงมาใส่)
      '', // H: Lng (ถ้ามีค่อยดึงมาใส่)
      JSON.stringify(payload.formData), // I: RawDataJSON
      '' // J: AdminComment (ล้างค่าเมื่อส่งแก้ไขใหม่)
    ];

    if (existingRowIndex > -1) {
      // ✏️ กรณีแก้ไข: อัปเดตคอลัมน์ B ถึง J (เว้น A ไว้เพื่อให้ ID คงเดิม)
      sheet.getRange(existingRowIndex, 2, 1, 9).setValues([[
        rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6], rowData[7], rowData[8], rowData[9]
      ]]);
      return { success: true, message: 'แก้ไขและส่งข้อมูลเรียบร้อยแล้ว สถานะกลับเป็น: รออนุมัติ' };
    } else {
      // ➕ กรณีส่งครั้งแรก: เพิ่มบรรทัดใหม่
      sheet.appendRow(rowData);
      return { success: true, message: 'ส่งข้อมูลรายงานเรียบร้อยแล้ว สถานะปัจจุบัน: รออนุมัติ' };
    }
  } catch (e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการบันทึก: ' + e.toString() };
  } finally {
    _invalidateDashboardCache();
    lock.releaseLock();
  }
}

function submitBulkData(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var roleCheck = checkRole(auth.userRole, IS_AGENCY_UP, 'submitBulkData');
  if (!roleCheck.allowed) return roleCheck.error;
  var callerAgency = auth.agencyId || payload.userAgencyId || payload.agencyId;
  var ownerCheck = checkAgencyOwnership(auth.userRole, callerAgency, payload.agencyId);
  if (!ownerCheck.allowed) return ownerCheck.error;

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Data');
  if (!sheet) {
    return { success: false, message: 'ไม่พบแผ่นงาน (Data)' };
  }

  if (!payload.rows || !Array.isArray(payload.rows)) {
    return { success: false, message: 'ข้อมูลนำเข้าไม่ถูกต้อง' };
  }

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000);
  } catch (e) {
    return { success: false, message: 'ระบบหนาแน่นชั่วคราว กรุณาลองใหม่อีกครั้งใน 10 วินาที' };
  }

  try {
    var timestamp = new Date();
    var timeStr = Utilities.formatDate(timestamp, "GMT+7", "dd/MM/yyyy HH:mm:ss");
    var baseIdTime = timestamp.getTime();
    var rowsToWrite = [];

    for (var i = 0; i < payload.rows.length; i++) {
      var rowData = payload.rows[i];
      var reportTitle = rowData.report_title || rowData.school_name || payload.formName || "-";
      
      var formData = rowData;
      if (!formData.report_title) {
        formData.report_title = reportTitle;
      }
      
      var row = [
        "RPT_" + (baseIdTime + i),
        timeStr,
        payload.agencyId,
        payload.formId,
        reportTitle,
        'รออนุมัติ',
        '',
        '',
        JSON.stringify(formData),
        ''
      ];
      rowsToWrite.push(row);
    }

    if (rowsToWrite.length > 0) {
      var lastRow = sheet.getLastRow();
      sheet.getRange(lastRow + 1, 1, rowsToWrite.length, 10).setValues(rowsToWrite);
    }

    return { success: true, message: 'นำเข้าข้อมูลสำเร็จทั้งหมด ' + rowsToWrite.length + ' รายการ เรียบร้อยแล้ว' };
  } catch (e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการนำเข้าข้อมูล: ' + e.toString() };
  } finally {
    _invalidateDashboardCache();
    lock.releaseLock();
  }
}

function deleteData(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'deleteData');
  if (!g.allowed) return g.error;
  
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000); // รอสิทธิ์ลบข้อมูลสูงสุด 30 วินาที
  } catch (e) {
    return { success: false, message: 'ระบบหนาแน่นชั่วคราว (Lock timeout) กรุณาลองใหม่อีกครั้ง' };
  }
  
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data');
    var data  = sheet.getDataRange().getValues();
    
    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]).trim()===String(payload.id).trim()) {
        sheet.deleteRow(i+1);
        logAction(auth.userRole,'Delete Data','ลบข้อมูล ID: '+payload.id);
        
        _invalidateDashboardCache();
        return { success:true, message:'ลบข้อมูลเรียบร้อยแล้ว' };
      }
    }
    return { success:false, message:'ไม่พบข้อมูลที่ต้องการลบ' };
  } catch(e) { 
    return { success:false, message:e.toString() }; 
  } finally {
    lock.releaseLock();
  }
}

/**
 * ─────────────────────────────────────────────
 * GET DATA: ดึงข้อมูลประวัติการรายงานไปแสดงผลที่ตาราง
 * ─────────────────────────────────────────────
 */
function getSubmittedData(payloadOrRole, agencyId) {
  var auth = _resolveAuthParam(payloadOrRole);
  if (auth.error) return auth.error;
  var userRole = auth.userRole;
  var resolvedAgency = auth.agencyId || agencyId;
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Data');
    if (!sheet) return [];

    var data = sheet.getDataRange().getValues();
    var result = [];
    
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row[0]) continue; // ข้ามแถวว่าง
      
      var rowAgencyId = String(row[2]).trim(); 
      var rowAgencyName = AGENCY_MAP[rowAgencyId] || rowAgencyId;
      var clientAgencyId = String(resolvedAgency || agencyId || '').trim();
      var clientAgencyName = AGENCY_MAP[clientAgencyId] || clientAgencyId;
      
      // 🎯 แก้ปัญหา Filter: ยอมให้ผ่านถ้าตรงกันทั้งในรูปแบบรหัส (OBEC_M) หรือชื่อไทย (สพม.สกลนคร)
      if (userRole === 'agency') {
        if (rowAgencyId !== clientAgencyId && rowAgencyId !== clientAgencyName && rowAgencyName !== clientAgencyId) {
          continue;
        }
      }
      
      var ts = row[1];
      var tsString = "";
      if (Object.prototype.toString.call(ts) === '[object Date]') {
        tsString = Utilities.formatDate(ts, "GMT+7", "dd/MM/yyyy HH:mm:ss");
      } else {
        tsString = String(ts || "");
      }
      
      result.push({
        id: String(row[0] || ''),             
        timestamp: tsString,      
        agencyId: rowAgencyId, // ยึดค่าเดิมจากแผ่นงาน       
        formId: String(row[3] || ''),         
        reportTitle: String(row[4] || ''),    
        status: String(row[5] || ''),         
        lat: String(row[6] || ''),            
        lng: String(row[7] || ''),            
        details: String(row[8] || '{}'),        
        adminComment: String(row[9] || '') 
      });
    }
    
    return result.reverse();

  } catch (e) {
    Logger.log('Error in getSubmittedData: ' + e.message);
    return [];
  }
}

// ─────────────────────────────────────────────
// 7. DASHBOARD — ประมวลผลสถิติและเตรียมข้อมูลแผนที่ (เวอร์ชันล่าสุด)
// ─────────────────────────────────────────────
function getDashboardData(payloadOrYear, filterAgency) {
  var fYear, fAgency;
  var isAgencyUser = false;
  var userAgencyId = '';
  
  if (payloadOrYear && typeof payloadOrYear === 'object') {
    var auth = _resolveAuth(payloadOrYear);
    checkRole(auth.userRole, IS_AGENCY_UP, 'getDashboardData');
    fYear   = payloadOrYear.filterYear   || 'all';
    fAgency = payloadOrYear.filterAgency || 'all';
    
    if (auth.userRole === ROLE_AGENCY) {
      isAgencyUser = true;
      userAgencyId = auth.agencyId;
      fAgency = userAgencyId; // บังคับดูเฉพาะสังกัดตนเอง
    }
  } else {
    // Legacy positional call — ยังรองรับเพื่อความ backward compat
    fYear   = payloadOrYear || 'all';
    fAgency = filterAgency  || 'all';
  }
  var CACHE_KEY = 'dashboard_' + fYear + '_' + fAgency;
  
  // ตรวจสอบข้อมูลจาก CacheService (Chunked Support)
  var cached = _cacheGetSmart(CACHE_KEY);
  if (cached) {
    cached._fromCache = true;
    return cached;
  }

  initSetup();
  var ss    = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Data');
  var data  = sheet.getDataRange().getValues();

  var totalSchools=0, totalStudents=0, totalTeachers=0, totalSpecial=0;
  var agencyCount={}, teacherCount={};
  var studentCount={'ก่อนประถม':0,'ประถม':0,'ม.ต้น':0,'ม.ปลาย':0,'ปวช/ปวส':0};
  var specialCount={'ออทิสติก':0,'ร่างกาย':0,'สติปัญญา':0};
  var pendingCount=0, latestApproved={};

  // ดึงโครงสร้าง Custom Fields จาก FormTemplates สำหรับ Dashboard
  var customDashFields={};
  try {
    var fSheet=ss.getSheetByName('FormTemplates');
    if (fSheet) {
      var fRows=fSheet.getDataRange().getValues();
      for (var fi=1;fi<fRows.length;fi++) {
        if (!fRows[fi][0]) continue;
        var cfg=[]; try { cfg=JSON.parse(fRows[fi][3]); } catch(e) {}
        cfg.forEach(function(f){ 
          if (f.dash===true&&f.name&&f.name.indexOf('custom_')===0&&!customDashFields[f.name]) {
            customDashFields[f.name]=f.dashLabel||f.label||f.name; 
          }
        });
      }
    }
  } catch(e) {}
  
  var customTotals={};
  Object.keys(customDashFields).forEach(function(k){ customTotals[k]=0; });

  // คัดกรองข้อมูลเฉพาะรายการที่ 'อนุมัติแล้ว' และตรงตาม Filter
  for (var i=1;i<data.length;i++) {
    var rowStatus = data[i][5];
    var rowAgency = data[i][2];
    
    var ts=data[i][1], yr='';
    if (ts instanceof Date) {
      yr=String(ts.getFullYear()+543);
    } else {
      // จับปีจากรูปแบบ dd/MM/yyyy ก่อน ถ้าไม่ตรงค่อย fallback หา 4 หลักทั่วไป
      var ym=String(ts).match(/\d{2}\/\d{2}\/(\d{4})/)||String(ts).match(/(\d{4})-\d{2}-\d{2}/);
      if (ym) { var y=parseInt(ym[1]); yr=String(y>2500?y:y+543); }
    }

    // ตรวจสอบเงื่อนไขปีและสังกัด
    if (fYear!=='all' && yr!==fYear) continue;
    if (fAgency!=='all' && rowAgency!==fAgency) continue;
    
    var isEligible = false;
    if (rowStatus === 'อนุมัติแล้ว') {
      isEligible = true;
    } else if (fAgency !== 'all' && (rowStatus === 'รออนุมัติ' || rowStatus === 'ส่งกลับแก้ไข')) {
      // สำหรับหน้าจอของสังกัด ยอมให้ดึงข้อมูลที่ส่งล่าสุดแม้ยังไม่อนุมัติ มาประมวลเป็นตัวเลขสถิติได้เพื่อไม่ให้สถิติเป็น 0
      isEligible = true;
    }

    if (isEligible) {
      var currentBest = latestApproved[rowAgency];
      if (!currentBest) {
        latestApproved[rowAgency] = data[i];
      } else {
        var currentStatus = currentBest[5];
        var incomingStatus = data[i][5];
        var updateBest = false;
        
        if (incomingStatus === 'อนุมัติแล้ว' && currentStatus !== 'อนุมัติแล้ว') {
          updateBest = true;
        } else if (incomingStatus === 'รออนุมัติ' && currentStatus === 'ส่งกลับแก้ไข') {
          updateBest = true;
        } else if (incomingStatus === currentStatus) {
          if (Number(data[i][0] || 0) > Number(currentBest[0] || 0)) {
            updateBest = true;
          }
        }
        
        if (updateBest) {
          latestApproved[rowAgency] = data[i];
        }
      }
    }
    
    if (rowStatus==='รออนุมัติ') pendingCount++;
  }

  // คำนวณผลรวมสถิติจากข้อมูลที่ผ่านการกรองแล้ว
  for (var agId in latestApproved) {
    var row=latestApproved[agId], rawJson=row[8];
    if (!rawJson) continue;
    try {
      var fd=JSON.parse(rawJson);
      var sch=Number(fd.school_total||0), std=Number(fd.student_total||0), tch=Number(fd.teacher_total||0);
      
      totalSchools+=sch; 
      totalStudents+=std; 
      totalTeachers+=tch;
      totalSpecial+=Number(fd.spc_autistic||0)+Number(fd.spc_physical||0)+Number(fd.spc_mental||0);
      
      agencyCount[agId]=(agencyCount[agId]||0)+sch;
      teacherCount[agId]=(teacherCount[agId]||0)+tch;
      
      studentCount['ก่อนประถม']+=Number(fd.std_pre||0);
      studentCount['ประถม']+=Number(fd.std_p||0);
      studentCount['ม.ต้น']+=Number(fd.std_m_ton||0);
      studentCount['ม.ปลาย']+=Number(fd.std_m_plai||0);
      studentCount['ปวช/ปวส']+=Number(fd.std_voc||0);
      
      specialCount['ออทิสติก']+=Number(fd.spc_autistic||0);
      specialCount['ร่างกาย']+=Number(fd.spc_physical||0);
      specialCount['สติปัญญา']+=Number(fd.spc_mental||0);
      
      Object.keys(customDashFields).forEach(function(k){ 
        if (fd[k]!=null&&fd[k]!=='') customTotals[k]=(customTotals[k]||0)+Number(fd[k]||0); 
      });
    } catch(e) {}
  }

  // เตรียมข้อมูล Marker สำหรับแผนที่ (ดึงเฉพาะที่มีพิกัดใน Sheet "GisCoords")
  var mapPoints=[];
  var allCoords = getAgencyGisCoords(); 
  
  for (var agId in allCoords) {
    var coords = allCoords[agId];
    if (!coords || !coords.lat || !coords.lng) continue;

    var hasData = !!latestApproved[agId];
    var mS=0, mSt=0, mT=0;
    
    if (hasData) {
      try {
        var _fd = JSON.parse(latestApproved[agId][8]);
        mS = Number(_fd.school_total||0);
        mSt = Number(_fd.student_total||0);
        mT = Number(_fd.teacher_total||0);
      } catch(e) {}
    }

    mapPoints.push({
      name: AGENCY_MAP[agId] || agId,
      agency: AGENCY_MAP[agId] || agId,
      agencyId: agId,
      lat: coords.lat,
      lng: coords.lng,
      schools: mS,
      students: mSt,
      teachers: mT,
      hasData: hasData
    });
  }

  // --- คำนวณอันดับการนำส่งข้อมูล (Leaderboard) สำหรับปี fYear ---
  var leaderboard = [];
  try {
    var fSheet = ss.getSheetByName('FormTemplates');
    var forms = [];
    if (fSheet) {
      var fRows = fSheet.getDataRange().getValues();
      for (var fi = 1; fi < fRows.length; fi++) {
        if (fRows[fi][0]) {
          forms.push({ formId: String(fRows[fi][0]), agencyId: String(fRows[fi][2]) });
        }
      }
    }

    var agKeys = Object.keys(AGENCY_MAP);
    var submissions = {};
    agKeys.forEach(function(k) { submissions[k] = {}; });

    for (var j = 1; j < data.length; j++) {
      var rowStatus = data[j][5];
      var rowAgency = data[j][2];
      var rowForm   = data[j][3];
      var ts = data[j][1];
      var yr = '';

      if (rowStatus === 'อนุมัติแล้ว' && submissions[rowAgency]) {
        if (ts instanceof Date) {
          yr = String(ts.getFullYear() + 543);
        } else {
          var ym = String(ts).match(/\d{2}\/\d{2}\/(\d{4})/) || String(ts).match(/(\d{4})-\d{2}-\d{2}/);
          if (ym) { var y = parseInt(ym[1]); yr = String(y > 2500 ? y : y + 543); }
        }
        if (fYear === 'all' || yr === fYear) {
          submissions[rowAgency][rowForm] = true;
        }
      }
    }

    agKeys.forEach(function(aid) {
      var targetForms = forms.filter(function(f) { return f.agencyId === 'ALL' || f.agencyId === aid; });
      var total = targetForms.length;
      var approved = 0;
      targetForms.forEach(function(f) {
        if (submissions[aid][f.formId] === true) {
          approved++;
        }
      });
      var pct = total > 0 ? Math.round(approved / total * 100) : 0;
      leaderboard.push({
        agencyId: aid,
        agencyName: AGENCY_MAP[aid],
        totalForms: total,
        approvedForms: approved,
        completionPct: pct
      });
    });

    leaderboard.sort(function(a, b) {
      if (b.completionPct !== a.completionPct) {
        return b.completionPct - a.completionPct;
      }
      return a.agencyName.localeCompare(b.agencyName, 'th');
    });
  } catch(e) {
    Logger.log('Error calculating leaderboard: ' + e.message);
  }

  // --- คำนวณความคืบหน้าการส่งงานและการแจ้งเตือนสำหรับสังกัดเดี่ยว ---
  var compliance = null;
  if (fAgency !== 'all') {
    try {
      // ดึงแบบฟอร์มทั้งหมดที่หน่วยงานนี้ต้องส่ง
      var assignedForms = getAvailableFormsForAgency(fAgency);
      
      var formStatuses = [];
      var totalRequired = assignedForms.length;
      var totalApproved = 0;
      var totalPending = 0;
      var totalRejected = 0;
      var totalNotSubmitted = 0;
      var recentSubmissions = [];
      
      // ดึงประวัติของสังกัดนี้ทั้งหมดในชีต Data
      var agencySubmissions = [];
      for (var i = 1; i < data.length; i++) {
        var rowAgency = data[i][2];
        if (rowAgency === fAgency) {
          var rowTimestamp = data[i][1];
          var yr = '';
          if (rowTimestamp instanceof Date) {
            yr = String(rowTimestamp.getFullYear() + 543);
          } else {
            var ym = String(rowTimestamp).match(/\d{2}\/\d{2}\/(\d{4})/) || String(rowTimestamp).match(/(\d{4})-\d{2}-\d{2}/);
            if (ym) { var y = parseInt(ym[1]); yr = String(y > 2500 ? y : y + 543); }
          }
          
          agencySubmissions.push({
            rowId: data[i][0],
            timestamp: String(data[i][1]),
            formId: data[i][3],
            formName: data[i][4],
            status: data[i][5] || 'รอดำเนินการ',
            year: yr,
            rawData: data[i]
          });
        }
      }
      
      // จัดกลุ่มเช็คสถานะการส่งงานปีปัจจุบัน
      assignedForms.forEach(function(f) {
        var matchingSubs = agencySubmissions.filter(function(sub) {
          return sub.formId === f.formId && (fYear === 'all' || sub.year === fYear);
        });
        
        // เรียงลำดับเอาตัวล่าสุด
        matchingSubs.sort(function(a, b) {
          return Number(b.rowId || 0) - Number(a.rowId || 0);
        });
        
        var status = 'ยังไม่ส่ง';
        var timestamp = '';
        if (matchingSubs.length > 0) {
          status = matchingSubs[0].status;
          timestamp = matchingSubs[0].timestamp;
          
          if (status === 'อนุมัติแล้ว') totalApproved++;
          else if (status === 'รออนุมัติ') totalPending++;
          else if (status === 'ส่งกลับแก้ไข') totalRejected++;
          else totalPending++;
        } else {
          totalNotSubmitted++;
        }
        
        formStatuses.push({
          formId: f.formId,
          formName: f.formName,
          status: status,
          timestamp: timestamp,
          deadline: f.deadline || ''
        });
      });
      
      // 5 รายการส่งล่าสุด
      agencySubmissions.sort(function(a, b) {
        return Number(b.rowId || 0) - Number(a.rowId || 0);
      });
      recentSubmissions = agencySubmissions.slice(0, 5).map(function(sub) {
        return {
          rowId: String(sub.rowId),
          formId: sub.formId,
          formName: sub.formName,
          timestamp: sub.timestamp,
          status: sub.status,
          year: sub.year
        };
      });
      
      compliance = {
        totalRequired: totalRequired,
        totalApproved: totalApproved,
        totalPending: totalPending,
        totalRejected: totalRejected,
        totalNotSubmitted: totalNotSubmitted,
        formStatuses: formStatuses,
        recentSubmissions: recentSubmissions
      };
    } catch(e) {
      Logger.log('Error calculating compliance: ' + e.message);
    }
  }

  var result = {
    totalSchools: totalSchools, 
    totalStudents: totalStudents, 
    totalTeachers: totalTeachers,
    totalSpecial: totalSpecial, 
    pendingCount: pendingCount,
    agencySummary: { 
      labels: Object.keys(agencyCount).map(function(k){ return AGENCY_MAP[k]||k; }), 
      values: Object.values(agencyCount) 
    },
    studentSummary: { labels: Object.keys(studentCount), values: Object.values(studentCount) },
    teacherSummary: { 
      labels: Object.keys(teacherCount).map(function(k){ return AGENCY_MAP[k]||k; }), 
      values: Object.values(teacherCount) 
    },
    specialSummary: { labels: Object.keys(specialCount), values: Object.values(specialCount) },
    mapPoints: mapPoints,
    leaderboard: leaderboard,
    customSummary: Object.keys(customDashFields).map(function(k){ 
      return { name: k, label: customDashFields[k], total: customTotals[k]||0 }; 
    }),
    isAgencyUser: isAgencyUser,
    userAgencyId: userAgencyId,
    compliance: compliance,
    _fromCache: false,
    _cachedAt: Utilities.formatDate(new Date(),"Asia/Bangkok","HH:mm:ss")
  };
  
  // บันทึกลง Cache เพื่อเพิ่มความเร็วในการเรียกครั้งต่อไป
  _cacheSet(CACHE_KEY, result, CACHE_TTL.DASHBOARD);
  return result;
}

// ─────────────────────────────────────────────
// 7b. AI CHATBOT — แชทบอทผู้บริหาร (PIN protected)
// ─────────────────────────────────────────────
function verifyChatbotPin(payload) {
  var auth = _resolveAuth(payload);
  if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'verifyChatbotPin');
  if (!g.allowed) return g.error;

  var storedPin = PropertiesService.getScriptProperties().getProperty('CHATBOT_PIN');
  if (!storedPin) return { success: false, message: 'ไม่พบ CHATBOT_PIN ใน Script Properties' };
  if (String(payload.pin).trim() !== String(storedPin).trim()) {
    logAction(auth.userRole, 'CHATBOT_PIN_FAIL', 'PIN ไม่ถูกต้อง');
    return { success: false };
  }
  logAction(auth.userRole, 'CHATBOT_UNLOCK', 'เข้าใช้งาน AI Chatbot สำเร็จ');
  return { success: true };
}

// ── Gemini shared helper — ใช้ร่วมกันทั้ง chatbot และ executive summary ──
function _callGemini(apiKey, contents, maxTokens, temperature, systemInstructionText) {
  var preferredModels = [
    'models/gemini-1.5-flash',
    'models/gemini-1.5-pro',
    'models/gemini-1.0-pro'
  ];
  
  var errors = [];
  for (var i = 0; i < preferredModels.length; i++) {
    var mName = preferredModels[i];
    try {
      var localContents = contents;
      var limitTokens = maxTokens || 1024;
      if (mName.indexOf('gemini-1.0') !== -1 && limitTokens > 2048) {
        limitTokens = 2048;
      }
      var payloadObj = {
        generationConfig: {
          maxOutputTokens: limitTokens,
          temperature: temperature || 0.4
        }
      };

      if (systemInstructionText) {
        if (mName.indexOf('gemini-1.0') === -1) {
          payloadObj.systemInstruction = {
            parts: [{ text: systemInstructionText }]
          };
          payloadObj.contents = localContents;
        } else {
          // Fallback for models that do not support systemInstruction (e.g. gemini-1.0-pro)
          localContents = [
            { role: 'user', parts: [{ text: systemInstructionText + '\n\n(รับทราบข้อกำหนดด้านบนแล้ว พร้อมคุยกับผู้ใช้)' }] },
            { role: 'model', parts: [{ text: 'รับทราบข้อกำหนดและบทบาทแล้วครับ พร้อมให้บริการ' }] }
          ].concat(contents);
          payloadObj.contents = localContents;
        }
      } else {
        payloadObj.contents = localContents;
      }

      var r = UrlFetchApp.fetch(
        'https://generativelanguage.googleapis.com/v1beta/' + mName + ':generateContent?key=' + apiKey.trim(),
        {
          method: 'post',
          contentType: 'application/json',
          muteHttpExceptions: true,
          payload: JSON.stringify(payloadObj)
        }
      );
      var code = r.getResponseCode();
      var responseText = r.getContentText();
      var body = JSON.parse(responseText);
      
      if (code === 200 && !body.error) {
        var candidates = body.candidates || [];
        var parts = candidates[0] && candidates[0].content && candidates[0].content.parts ? candidates[0].content.parts : [];
        var txt = parts.map(function(p) { return p.text || ''; }).join('');
        if (txt) {
          return { ok: true, text: txt, model: mName.replace('models/', '') };
        }
      } else {
        var errMsg = body.error ? body.error.message : 'HTTP ' + code;
        errors.push(mName + ' (' + errMsg + ')');
      }
    } catch(e) {
      errors.push(mName + ' (' + e.message + ')');
    }
  }
  
  // Fallback: dynamic models check if all preferred models failed
  try {
    var listResp = UrlFetchApp.fetch(
      'https://generativelanguage.googleapis.com/v1beta/models?key=' + apiKey.trim(),
      { muteHttpExceptions: true }
    );
    if (listResp.getResponseCode() === 200) {
      var models = (JSON.parse(listResp.getContentText()).models || [])
        .filter(function(m){ return (m.supportedGenerationMethods||[]).indexOf('generateContent') !== -1; })
        .sort(function(a,b){
          var s = function(n){ return n.indexOf('1.5-flash')!==-1?0:n.indexOf('flash')!==-1?1:n.indexOf('pro')!==-1?2:3; };
          return s(a.name)-s(b.name);
        });
      for (var mi = 0; mi < models.length; mi++) {
        var fallbackModel = models[mi].name;
        if (preferredModels.indexOf(fallbackModel) !== -1) continue; // already tried
        try {
          var localFallbackContents = contents;
          var limitFallbackTokens = maxTokens || 1024;
          if (fallbackModel.indexOf('gemini-1.0') !== -1 && limitFallbackTokens > 2048) {
            limitFallbackTokens = 2048;
          }
          var fallbackPayload = {
            generationConfig: {
              maxOutputTokens: limitFallbackTokens,
              temperature: temperature || 0.4
            }
          };
          if (systemInstructionText) {
            if (fallbackModel.indexOf('gemini-1.0') === -1) {
              fallbackPayload.systemInstruction = { parts: [{ text: systemInstructionText }] };
              fallbackPayload.contents = localFallbackContents;
            } else {
              localFallbackContents = [
                { role: 'user', parts: [{ text: systemInstructionText + '\n\n(รับทราบข้อกำหนดด้านบนแล้ว)' }] },
                { role: 'model', parts: [{ text: 'รับทราบครับ' }] }
              ].concat(contents);
              fallbackPayload.contents = localFallbackContents;
            }
          } else {
            fallbackPayload.contents = localFallbackContents;
          }

          var rFallback = UrlFetchApp.fetch(
            'https://generativelanguage.googleapis.com/v1beta/' + fallbackModel + ':generateContent?key=' + apiKey.trim(),
            { method:'post', contentType:'application/json', muteHttpExceptions:true,
              payload: JSON.stringify(fallbackPayload) }
          );
          if (rFallback.getResponseCode() === 200) {
            var bodyFallback = JSON.parse(rFallback.getContentText());
            var partsFallback = bodyFallback.candidates && bodyFallback.candidates[0] && bodyFallback.candidates[0].content &&
                                bodyFallback.candidates[0].content.parts ? bodyFallback.candidates[0].content.parts : [];
            var txtFallback = partsFallback.map(function(p) { return p.text || ''; }).join('');
            if (txtFallback) {
              return { ok: true, text: txtFallback, model: fallbackModel.replace('models/','') };
            }
          }
        } catch(e) {}
      }
    }
  } catch(e) {}

  return { ok: false, error: 'ลองทุก model แล้วไม่สำเร็จ: ' + errors.join(', ') };
}

// ── ดึงข้อมูลดิบล่าสุด (อนุมัติแล้ว) จาก Data sheet ──
function _cbGetLatestApprovedData(agencyFilter) {
  var FIELD_LABELS = {
    school_total:'สถานศึกษา(แห่ง)',student_total:'ผู้เรียนรวม(คน)',teacher_total:'ครูและบุคลากร(คน)',
    std_pre:'ก่อนประถม(คน)',std_p:'ประถม(คน)',std_m_ton:'ม.ต้น(คน)',std_m_plai:'ม.ปลาย(คน)',
    std_voc:'ปวช/ปวส(คน)',spc_autistic:'ออทิสติก(คน)',spc_physical:'พิการร่างกาย(คน)',
    spc_mental:'บกพร่องสติปัญญา(คน)',building_count:'อาคารเรียน(หลัง)',
    toilet_count:'ห้องน้ำ(ห้อง)',computer_count:'คอมพิวเตอร์(เครื่อง)',
    internet_school:'มีอินเทอร์เน็ต(แห่ง)',budget_total:'งบประมาณ(บาท)',
    dropout_count:'ออกกลางคัน(คน)',graduate_count:'จบการศึกษา(คน)'
  };
  try {
    var ss    = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Data');
    if (!sheet) return {};
    var rows  = sheet.getDataRange().getValues();
    var latest = {};
    for (var i = 1; i < rows.length; i++) {
      var ag  = String(rows[i][2]);
      var st  = String(rows[i][5]);
      var ts  = rows[i][1];
      if (st !== 'อนุมัติแล้ว') continue;
      if (agencyFilter && agencyFilter !== 'all' && ag !== agencyFilter) continue;
      if (!latest[ag] || ts > latest[ag].ts) {
        var fd = {};
        try { fd = JSON.parse(rows[i][8]); } catch(e) {}
        latest[ag] = { ts: ts, title: String(rows[i][4]), fields: fd };
      }
    }
    // แปลงเป็น text กระชับ
    var lines = [];
    Object.keys(latest).forEach(function(agId) {
      var rec  = latest[agId];
      var name = AGENCY_MAP[agId] || agId;
      var flds = Object.keys(rec.fields)
        .filter(function(k){ return k!=='report_title' && rec.fields[k]!=='' && rec.fields[k]!==null && rec.fields[k]!==undefined; })
        .map(function(k){
          var lbl = FIELD_LABELS[k] || k;
          var val = rec.fields[k];
          return lbl + ': ' + (typeof val === 'number' ? val.toLocaleString() : val);
        });
      if (flds.length) lines.push('[' + name + '] ' + rec.title + '\n  ' + flds.join(', '));
    });
    return lines.length ? lines.join('\n') : '(ยังไม่มีข้อมูลที่อนุมัติแล้ว)';
  } catch(e) { return '(โหลดข้อมูลดิบไม่สำเร็จ: ' + e.message + ')'; }
}

// ── Smart context builder — วิเคราะห์คำถาม แล้วดึงเฉพาะข้อมูลที่เกี่ยวข้อง ──
function _cbBuildContext(question, payload) {
  var q = question.toLowerCase();
  var lines = [];
  lines.push('วันที่: ' + Utilities.formatDate(new Date(), 'Asia/Bangkok', 'dd/MM/yyyy HH:mm น.'));

  // ── ตรวจ intent ──
  var wantsStatus   = /สถานะ|ส่งข้อมูล|อนุมัติ|รออนุมัติ|ยังไม่ส่ง|ค้างส่ง|ครบถ้วน|ความคืบหน้า/.test(q);
  var wantsRawData  = /ข้อมูล|ตัวเลข|จำนวน|สถิติ|รายงาน|เปรียบ|เทียบ|สูงสุด|ต่ำสุด|มากที่สุด|น้อยที่สุด|แยก|ทุกสังกัด|ภาพรวม|ดู|แสดง/.test(q);
  var wantsSummary  = /สรุป|ภาพรวม|โดยรวม|ทั้งหมด|ทั้งจังหวัด/.test(q);

  // ── ตรวจชื่อสังกัดในคำถาม ──
  var targetAgency = null;
  var agSearchMap = {
    'OBEC_1':['สพป.*เขต.?1','ประถมเขต1','สพป 1','สพป1'],
    'OBEC_2':['สพป.*เขต.?2','ประถมเขต2','สพป 2','สพป2'],
    'OBEC_3':['สพป.*เขต.?3','ประถมเขต3','สพป 3','สพป3'],
    'OBEC_M':['สพม','มัธยม','สพม.สกลนคร'],
    'VEC':['อาชีวศึกษา','อาชีวะ','vec'],
    'OPEC':['สช','เอกชน','opec'],
    'DLA':['อปท','ท้องถิ่น','dla'],
    'DOLE':['สกร','ส่งเสริมการเรียนรู้','กศน','dole'],
    'BUDDHIST':['พระปริยัติธรรม','พุทธ','buddhist'],
    'BPP':['ตชด','bpp'],
    'SPECIAL':['การศึกษาพิเศษ','พิเศษ','special'],
    'HIGHER':['อุดมศึกษา','มหาวิทยาลัย','higher'],
    'NURSERY':['อนุบาล','สถานรับเลี้ยง','ศพด','nursery']
  };
  Object.keys(agSearchMap).forEach(function(agId) {
    agSearchMap[agId].forEach(function(pat) {
      if (!targetAgency && new RegExp(pat).test(q)) targetAgency = agId;
    });
  });

  // ── ดึง dashboard summary (เสมอ) ──
  var dash;
  try { dash = getDashboardData({ sessionToken: payload.sessionToken, filterYear: 'all', filterAgency: 'all' }); } catch(e) {}
  if (dash) {
    lines.push('\n=== สถิติภาพรวมจังหวัดสกลนคร ===');
    lines.push('สถานศึกษา ' + dash.totalSchools + ' แห่ง | ผู้เรียน ' + dash.totalStudents.toLocaleString() + ' คน | ครู ' + dash.totalTeachers.toLocaleString() + ' คน | พิการ ' + dash.totalSpecial.toLocaleString() + ' คน');
    if (dash.studentSummary && dash.studentSummary.labels) {
      lines.push('ผู้เรียนแยกระดับ: ' + dash.studentSummary.labels.map(function(l,i){ return l+' '+dash.studentSummary.values[i].toLocaleString(); }).join(' | '));
    }
  }

  // ── สถานะการรายงาน (เมื่อถามเรื่องสถานะ หรือภาพรวม) ──
  if (wantsStatus || wantsSummary) {
    var mon;
    try { mon = getMonitoringData(payload); } catch(e) {}
    if (mon && mon.overall) {
      var ov = mon.overall;
      lines.push('\n=== สถานะการรายงาน ===');
      lines.push('ภาพรวม: ' + ov.overallPct + '% (อนุมัติ ' + ov.totalApproved + '/' + ov.totalForms + ' แบบ | รอ ' + ov.totalPending + ' | ส่งกลับ ' + ov.totalRejected + ' | ยังไม่ส่ง ' + ov.totalNotSent + ')');
      if (mon.agencySummary) {
        mon.agencySummary.forEach(function(a) {
          lines.push(a.agencyName + ': ' + a.completionPct + '% | ส่ง ' + a.submitted + '/' + a.totalForms + ' | อนุมัติ ' + a.approved + ' | รอ ' + a.pending + ' | ยังไม่ส่ง ' + a.notSent);
        });
      }
    }
  }

  // ── ข้อมูลดิบจากฐานข้อมูล ──
  if (wantsRawData || wantsSummary || targetAgency) {
    var filter = targetAgency || 'all';
    lines.push('\n=== ข้อมูลดิบจากฐานข้อมูล (รายงานล่าสุดที่อนุมัติแล้ว' + (targetAgency ? ' — ' + (AGENCY_MAP[targetAgency]||targetAgency) : ' ทุกสังกัด') + ') ===');
    lines.push(_cbGetLatestApprovedData(filter));
  }

  return lines.join('\n');
}

function askChatbot(payload) {
  var auth = _resolveAuth(payload);
  if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'askChatbot');
  if (!g.allowed) return g.error;

  var apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) return { success: false, message: 'ไม่พบ GEMINI_API_KEY ใน Script Properties' };

  var userMessage = String(payload.message || '').trim();
  if (!userMessage) return { success: false, message: 'ไม่มีข้อความ' };

  var history = payload.history || [];

  // สร้าง context อัจฉริยะตามคำถาม
  var contextData = _cbBuildContext(userMessage, payload);

  var systemInstructionText = 'คุณคือ AI ผู้ช่วยวิเคราะห์ข้อมูลสารสนเทศการศึกษาของจังหวัดสกลนคร (EduData Sakon AI Assistant)\n'
    + 'มีหน้าที่ตอบคำถามผู้บริหารและผู้ใช้ระดับนโยบายด้วยภาษาไทยที่สุภาพ เป็นทางการ น่าเชื่อถือ และมีความเป็นมืออาชีพสูง\n\n'
    + '--- กฎในการตอบคำถาม ---\n'
    + '1. ตอบคำถามอย่างละเอียด ครบถ้วน และครอบคลุมหัวข้อที่ผู้ใช้ถาม โดยให้สรุปประเด็นสำคัญและวิเคราะห์ความสัมพันธ์ของตัวเลขให้เห็นภาพชัดเจน\n'
    + '2. เมื่อแสดงตัวเลขสถิติ ให้จัดหมวดหมู่ แยกตามสังกัด หรือนำเสนอในรูปแบบรายการ (bullet points) หรือตารางข้อความเพื่อให้ผู้บริหารอ่านง่ายและเข้าใจได้ทันที\n'
    + '3. อ้างอิงข้อมูลดิบและตัวเลขสถิติจากชุดข้อมูลที่ได้รับด้านล่างนี้เท่านั้น ห้ามประดิษฐ์หรือคาดเดาตัวเลขที่ไม่มีอยู่ในชุดข้อมูล\n'
    + '4. หากในชุดข้อมูลไม่มีสิ่งที่ผู้ใช้ถาม ให้แจ้งผู้ใช้อย่างสุภาพว่าไม่มีข้อมูลในระบบ และแนะนำสังกัดหรือแบบฟอร์มที่ใกล้เคียงแทน (ถ้ามี)\n\n'
    + '--- ชุดข้อมูลสารสนเทศการศึกษา (EduData Context) ---\n'
    + contextData;

  // สร้าง contents สำหรับ Gemini (multi-turn) จากประวัติการคุยจริง
  var contents = [];
  history.forEach(function(h) {
    contents.push({
      role: h.role === 'model' ? 'model' : 'user',
      parts: [{ text: h.text || '' }]
    });
  });
  contents.push({
    role: 'user',
    parts: [{ text: userMessage }]
  });

  try {
    var result = _callGemini(apiKey, contents, 1024, 0.5, systemInstructionText);
    if (!result.ok) return { success: false, message: result.error };
    return { success: true, reply: result.text, model: result.model };
  } catch(e) {
    return { success: false, message: 'เรียก Gemini ไม่สำเร็จ: ' + e.message };
  }
}

// ─────────────────────────────────────────────
// 7c. AI EXECUTIVE SUMMARY — สรุปเชิงนโยบายด้วย Gemini AI
// ─────────────────────────────────────────────
function generateExecutiveSummary(payload) {
  var auth = _resolveAuth(payload);
  if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'generateExecutiveSummary');
  if (!g.allowed) return g.error;

  var apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) return { success: false, message: 'ไม่พบ GEMINI_API_KEY ใน Script Properties\nกรุณาเพิ่ม key ใน Apps Script → Project Settings → Script Properties\n(รับ API Key ฟรีได้ที่ aistudio.google.com)' };

  // ดึงข้อมูล dashboard และ monitoring
  var dash, mon;
  try { dash = getDashboardData({ sessionToken: payload.sessionToken, filterYear: payload.filterYear || 'all', filterAgency: 'all' }); } catch(e) { dash = null; }
  try { mon  = getMonitoringData(payload); } catch(e) { mon = null; }

  var yearLabel = payload.filterYear && payload.filterYear !== 'all' ? 'ปีการศึกษา ' + payload.filterYear : 'ทุกปีการศึกษา (ข้อมูลล่าสุดที่อนุมัติแล้ว)';

  // สร้าง context สถิติแบบกระชับ
  var ctx = [];
  ctx.push('=== ข้อมูลสถิติการศึกษาจังหวัดสกลนคร : ' + yearLabel + ' ===\n');

  if (dash) {
    ctx.push('## ภาพรวมจังหวัด');
    ctx.push('- สถานศึกษา: ' + dash.totalSchools.toLocaleString() + ' แห่ง');
    ctx.push('- ผู้เรียนรวม: ' + dash.totalStudents.toLocaleString() + ' คน');
    ctx.push('- ครูและบุคลากร: ' + dash.totalTeachers.toLocaleString() + ' คน');
    ctx.push('- นักเรียนพิการ: ' + dash.totalSpecial.toLocaleString() + ' คน');
    ctx.push('- รายงานรออนุมัติ: ' + (dash.pendingCount || 0) + ' รายการ\n');

    if (dash.studentSummary && dash.studentSummary.labels) {
      ctx.push('## ผู้เรียนจำแนกตามระดับการศึกษา');
      dash.studentSummary.labels.forEach(function(lbl, i) {
        ctx.push('- ' + lbl + ': ' + (dash.studentSummary.values[i] || 0).toLocaleString() + ' คน');
      });
      ctx.push('');
    }

    if (dash.specialSummary && dash.specialSummary.labels) {
      ctx.push('## นักเรียนที่มีความต้องการพิเศษ');
      dash.specialSummary.labels.forEach(function(lbl, i) {
        ctx.push('- ' + lbl + ': ' + (dash.specialSummary.values[i] || 0).toLocaleString() + ' คน');
      });
      ctx.push('');
    }

    if (dash.agencySummary && dash.agencySummary.labels && dash.agencySummary.labels.length > 0) {
      ctx.push('## จำนวนสถานศึกษาแยกตามสังกัด');
      dash.agencySummary.labels.forEach(function(lbl, i) {
        ctx.push('- ' + lbl + ': ' + (dash.agencySummary.values[i] || 0) + ' แห่ง');
      });
      ctx.push('');
    }
  }

  if (mon && mon.overall) {
    var ov = mon.overall;
    ctx.push('## สถานะการรายงานข้อมูล');
    ctx.push('- ภาพรวมความครบถ้วน: ' + ov.overallPct + '% (' + ov.totalApproved + '/' + ov.totalForms + ' แบบรายงาน)');
    ctx.push('- อนุมัติแล้ว: ' + ov.totalApproved + ' | รออนุมัติ: ' + ov.totalPending + ' | ส่งกลับแก้ไข: ' + ov.totalRejected + ' | ยังไม่ส่ง: ' + ov.totalNotSent + '\n');

    if (mon.agencySummary) {
      var notComplete = mon.agencySummary.filter(function(a){ return a.completionPct < 100; }).sort(function(a,b){ return a.completionPct - b.completionPct; });
      if (notComplete.length > 0) {
        ctx.push('## สังกัดที่ยังรายงานไม่ครบ');
        notComplete.forEach(function(a) {
          ctx.push('- ' + a.agencyName + ': ' + a.completionPct + '% (ยังไม่ส่ง ' + a.notSent + ' แบบ, รออนุมัติ ' + a.pending + ' แบบ)');
        });
        ctx.push('');
      }
      var complete = mon.agencySummary.filter(function(a){ return a.completionPct === 100; });
      if (complete.length > 0) {
        ctx.push('## สังกัดที่รายงานครบถ้วน 100%');
        ctx.push(complete.map(function(a){ return a.agencyName; }).join(', '));
        ctx.push('');
      }
    }
  }

  var systemInstruction = 'คุณคือผู้เชี่ยวชาญด้านข้อมูลสารสนเทศการศึกษาระดับนโยบาย ปฏิบัติงานเป็น AI วิเคราะห์ข้อมูลและสถิติให้ศึกษาธิการจังหวัดสกลนคร';

  var prompt = 'กรุณาประมวลผลข้อมูลสถิติจังหวัดสกลนครด้านล่างนี้ และเขียนวิเคราะห์เชิงลึก (Executive Summary) สำหรับผู้บริหารการศึกษา\n\n' +
    ctx.join('\n') + '\n\n' +
    '--- ข้อกำหนดการจัดทำบทวิเคราะห์ ---\n' +
    'จงเขียน Executive Summary เชิงนโยบายภาษาไทยที่เป็นทางการ โดยวิเคราะห์ข้อมูลและอธิบายอย่างประณีต ครบถ้วนตามหัวข้อ ไม่ย่อข้อมูลให้สั้นจนเกินไป ให้แยกเนื้อหาออกเป็นหัวข้อดังนี้:\n' +
    '1. **บทสรุปและภาพรวมจังหวัด** — การวิเคราะห์สถานการณ์รวมของทั้งจังหวัด (สัดส่วนนักเรียน/ครู/โรงเรียน แยกตามสังกัดอย่างครบถ้วน)\n' +
    '2. **จุดเด่นและพัฒนาการเชิงบวก** — สังกัดหรือข้อมูลส่วนที่มีผลสำเร็จดี\n' +
    '3. **ประเด็นที่ต้องเฝ้าระวัง** — ความเสี่ยงหรือปัญหาที่ระบุจากสถิติ (เช่น สังกัดที่ส่งข้อมูลไม่ครบ หรือการวิเคราะห์สัดส่วนต่าง ๆ)\n' +
    '4. **ข้อเสนอแนะเชิงนโยบาย** — ข้อเสนอแนวทางแก้ไขหรือแผนปฏิบัติการที่เป็นรูปธรรมสำหรับผู้บริหาร\n' +
    '5. **สรุปย่อสำหรับผู้บริหาร** — บทสรุปสาระสำคัญสั้น ๆ (Key Takeaways)\n\n' +
    'เขียนตอบด้วยภาษาราชการที่เป็นทางการ ชัดเจน น่าเชื่อถือ อ้างอิงตัวเลขจริงจากข้อมูลที่ให้ไว้เท่านั้น ห้ามแต่งเติมข้อมูลใดๆ';

  try {
    var result = _callGemini(apiKey, [{ role:'user', parts:[{ text: prompt }] }], 8192, 0.4, systemInstruction);
    if (!result.ok) return { success: false, message: result.error };
    logAction(auth.userRole, 'AI_SUMMARY', 'Executive Summary สำเร็จ model=' + result.model + ' (' + yearLabel + ')');
    return {
      success: true,
      summary: result.text,
      yearLabel: yearLabel,
      modelUsed: result.model,
      generatedAt: Utilities.formatDate(new Date(), 'Asia/Bangkok', 'dd/MM/yyyy HH:mm น.')
    };
  } catch(e) {
    return { success: false, message: 'เรียก Gemini API ไม่สำเร็จ: ' + e.message };
  }
}

// ─────────────────────────────────────────────
// 8. AUDIT LOGS — ไม่ cache (ต้องแสดง real-time)
// ─────────────────────────────────────────────
function getAuditLogs(payloadOrRole) {
  var auth = _resolveAuthParam(payloadOrRole); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getAuditLogs');
  if (!g.allowed) return g.error;
  initSetup();
  var sheet  = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AuditLogs');
  var data   = sheet.getDataRange().getDisplayValues();
  var result = [];
  for (var i=data.length-1;i>=1&&result.length<150;i--) {
    if (!data[i][0]) continue;
    result.push({ timestamp:data[i][0], role:data[i][1], action:data[i][2], details:data[i][3] });
  }
  return result;
}

// ─────────────────────────────────────────────
// 9. SYSTEM RESET
// ─────────────────────────────────────────────
function clearYearlyData(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_SUPER, 'clearYearlyData');
  if (!g.allowed) return g.error;
  var superPass = (function(){
    var s=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var d=s.getDataRange().getValues();
    for (var i=1;i<d.length;i++) { if (String(d[i][0]).toLowerCase()==='super') return String(d[i][1]||'').trim(); }
    return null;
  })();
  if (!superPass||!_verifyPassword(payload.password, superPass)) {
    logAction(auth.userRole,'SECURITY_DENY','Reset ล้มเหลว: รหัสผ่านไม่ถูกต้อง');
    return { success:false, message:'รหัสผ่านยืนยันไม่ถูกต้อง ปฏิเสธการล้างข้อมูล' };
  }
  try {
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var dataSheet=ss.getSheetByName('Data'), lastRow=dataSheet.getLastRow();
    if (lastRow>1) {
      var year=new Date().getFullYear(), archiveName='Archive_'+year;
      var archSheet=ss.getSheetByName(archiveName);
      if (!archSheet) { archSheet=ss.insertSheet(archiveName); archSheet.appendRow(['ID','Timestamp','AgencyID','FormID','ReportTitle','Status','Lat','Lng','RawDataJSON','AdminComment']); archSheet.getRange('A1:J1').setFontWeight('bold').setBackground('#fce8e6'); }
      var rows=dataSheet.getRange(2,1,lastRow-1,dataSheet.getLastColumn()).getValues();
      archSheet.getRange(archSheet.getLastRow()+1,1,rows.length,rows[0].length).setValues(rows);
      dataSheet.getRange(2,1,lastRow-1,dataSheet.getLastColumn()).clearContent();
    }
    logAction(auth.userRole,'SYSTEM RESET','Archive & Clear ประจำปีโดย: '+(auth.username||payload.userName||auth.userRole));
    _invalidateDashboardCache(); // ล้าง cache หลัง reset
    return { success:true, message:'สำรองข้อมูลและล้างฐานข้อมูลเรียบร้อยแล้ว' };
  } catch(e) { return { success:false, message:e.toString() }; }
}

// ─────────────────────────────────────────────
// 10. GIS COORDINATES — cache 30 นาที (Enhanced for Advanced Reporting)
// ─────────────────────────────────────────────
function saveAgencyGisCoord(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_SUPER, 'saveAgencyGisCoord');
  if (!g.allowed) return g.error;
  if (!AGENCY_MAP[payload.agencyId]) return { success:false, message:'รหัสสังกัด "'+payload.agencyId+'" ไม่ถูกต้อง' };
  
  var lat=Number(payload.lat), lng=Number(payload.lng);
  
  // ตรวจสอบพิกัดให้อยู่ในขอบเขตประเทศไทย (ละติจูด 5-21, ลองจิจูด 97-106)
  if (isNaN(lat)||isNaN(lng)||lat<5||lat>21||lng<97||lng>106) {
    return { success:false, message:'พิกัดอยู่นอกขอบเขตประเทศไทย กรุณาระบุพิกัดที่ถูกต้อง' };
  }
  
  try {
    initSetup();
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var sheet=ss.getSheetByName('GisCoords');
    
    if (!sheet) { 
      sheet=ss.insertSheet('GisCoords'); 
      sheet.appendRow(['AgencyID','Lat','Lng','UpdatedBy','UpdatedAt']); 
      sheet.getRange('A1:E1').setFontWeight('bold').setBackground('#e6f4ea'); 
      sheet.setFrozenRows(1); 
    }
    
    var data=sheet.getDataRange().getValues();
    var ts=Utilities.formatDate(new Date(),"Asia/Bangkok","dd/MM/yyyy HH:mm:ss");
    var updated=false;
    
    for (var i=1;i<data.length;i++) {
      if (data[i][0]===payload.agencyId) { 
        sheet.getRange(i+1,2).setValue(lat); 
        sheet.getRange(i+1,3).setValue(lng); 
        sheet.getRange(i+1,4).setValue(auth.userRole);
        sheet.getRange(i+1,5).setValue(ts); 
        updated=true; 
        break;
      }
    }
    
    if (!updated) sheet.appendRow([payload.agencyId,lat,lng,auth.userRole,ts]);
    logAction(auth.userRole,'Update GIS','บันทึกพิกัด '+payload.agencyId+': '+lat+', '+lng);
    
    _cacheInvalidate(['gis_coords']); // invalidate GIS cache
    return { success:true, message:'บันทึกพิกัด '+(AGENCY_MAP[payload.agencyId])+' เรียบร้อยแล้ว' };
    
  } catch(e) { 
    return { success:false, message:e.toString() }; 
  }
}

function getAgencyGisCoords() {
  var CACHE_KEY = 'gis_coords';
  var cached = _cacheGet(CACHE_KEY);
  if (cached) return cached;

  initSetup();
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('GisCoords');
  var result = {}; // เปลี่ยนจากเดิมที่ดึงค่าจาก GIS_COORDS มาเป็น Object ว่าง

  if (sheet) {
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (!data[i][0]) continue;
      var lat = Number(data[i][1]), lng = Number(data[i][2]);
      // เก็บเฉพาะสังกัดที่มีการระบุพิกัด Latitude และ Longitude ที่ถูกต้องใน Sheet
      if (!isNaN(lat) && !isNaN(lng) && lat !== 0 && lng !== 0) {
        result[data[i][0]] = { lat: lat, lng: lng };
      }
    }
  }
  
  _cacheSet(CACHE_KEY, result, CACHE_TTL.GIS);
  return result;
}

// ─────────────────────────────────────────────
// ADVANCED REPORTING: Year-over-Year (YoY) Analytics
// ─────────────────────────────────────────────
function getYoYData() {
  var CACHE_KEY = 'yoy_data';
  var cached = _cacheGet(CACHE_KEY);
  if (cached) return cached;

  try {
    initSetup();
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var sheet=ss.getSheetByName('Data');
    if (!sheet) return null;
    
    var data=sheet.getDataRange().getValues();
    var byYear={};
    
    for (var i=1;i<data.length;i++) {
      if (data[i][5]!=='อนุมัติแล้ว') continue;
      var ts=data[i][1]; 
      if (!ts) continue;
      var yr='';
      
      if (ts instanceof Date) {
        yr=String(ts.getFullYear()+543);
      } else {
        var m=String(ts).match(/\d{2}\/\d{2}\/(\d{4})/)||String(ts).match(/(\d{4})-\d{2}-\d{2}/);
        if (m) { var y=parseInt(m[1]); yr=String(y>2500?y:y+543); }
      }
      if (!yr) continue;
      
      if (!byYear[yr]) {
        byYear[yr]={ schools:0, students:0, teachers:0, count:0 };
      }
      
      var fd={};
      try { 
        fd=JSON.parse(data[i][8]); 
      } catch(e) {}
      
      byYear[yr].schools+=Number(fd.school_total||0); 
      byYear[yr].students+=Number(fd.student_total||0); 
      byYear[yr].teachers+=Number(fd.teacher_total||0); 
      byYear[yr].count++;
    }
    
    var years=Object.keys(byYear).sort();
    
    if (years.length<2) {
      // ป้องกันกราฟบั๊กกรณีเพิ่งมีข้อมูลปีแรก (Zero-state handling)
      if (years.length === 1) {
         var y1 = years[0];
         var resSingle = {
           years: years,
           schools: [byYear[y1].schools],
           students: [byYear[y1].students],
           teachers: [byYear[y1].teachers],
           growth: { schools: ['0%'], students: ['0%'], teachers: ['0%'] }
         };
         _cacheSet(CACHE_KEY, resSingle, CACHE_TTL.DASHBOARD);
         return resSingle;
      }
      return null;
    }
    
    var growthSchools = ['0%'];
    var growthStudents = ['0%'];
    var growthTeachers = ['0%'];
    
    // คำนวณอัตราการเติบโต (Growth Rate % เทียบกับปีก่อนหน้า)
    for (var j=1; j<years.length; j++) {
       var prevY = years[j-1];
       var currY = years[j];
       
       var calcGrowth = function(curr, prev) {
         if (prev === 0) return curr > 0 ? '+100%' : '0%';
         var pct = ((curr - prev) / prev) * 100;
         return (pct > 0 ? '+' : '') + pct.toFixed(2) + '%';
       };
       
       growthSchools.push(calcGrowth(byYear[currY].schools, byYear[prevY].schools));
       growthStudents.push(calcGrowth(byYear[currY].students, byYear[prevY].students));
       growthTeachers.push(calcGrowth(byYear[currY].teachers, byYear[prevY].teachers));
    }

    var result = { 
      years: years, 
      schools: years.map(function(y){ return byYear[y].schools; }), 
      students: years.map(function(y){ return byYear[y].students; }), 
      teachers: years.map(function(y){ return byYear[y].teachers; }),
      growth: {
        schools: growthSchools,
        students: growthStudents,
        teachers: growthTeachers
      }
    };
    
    _cacheSet(CACHE_KEY, result, CACHE_TTL.DASHBOARD);
    return result;
    
  } catch(e) { 
    return null;
  }
}

// ─────────────────────────────────────────────
// 11. MONITORING — สรุปสถานะการส่งข้อมูลของทุกสังกัด
// ─────────────────────────────────────────────
function getMonitoringData(payloadOrRole) {
  var auth = _resolveAuthParam(payloadOrRole); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getMonitoringData');
  if (!g.allowed) return g.error;
  var CACHE_KEY = 'monitoring_all';
  var cached = _cacheGetSmart(CACHE_KEY);
  if (cached) { cached._fromCache = true; return cached; }
  try {
    initSetup();
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var formSheet=ss.getSheetByName('FormTemplates');
    var forms=[];
    if (formSheet) { var fRows=formSheet.getDataRange().getValues(); for (var i=1;i<fRows.length;i++) { if (fRows[i][0]) forms.push({ formId:String(fRows[i][0]), formName:String(fRows[i][1]), agencyId:String(fRows[i][2]) }); } }
    var dataSheet=ss.getSheetByName('Data');
    var dataRows=dataSheet?dataSheet.getDataRange().getValues():[[]];
    var agKeys=['OBEC_1','OBEC_2','OBEC_3','OBEC_M','VEC','OPEC','DLA','DOLE','BUDDHIST','BPP','SPECIAL','HIGHER','NURSERY'];
    var agNames={'OBEC_1':'สพป.สกลนคร เขต 1','OBEC_2':'สพป.สกลนคร เขต 2','OBEC_3':'สพป.สกลนคร เขต 3','OBEC_M':'สพม.สกลนคร','VEC':'อาชีวศึกษา','OPEC':'สช. (เอกชน)','DLA':'อปท. (ท้องถิ่น)','DOLE':'สกร. (ส่งเสริมการเรียนรู้)','BUDDHIST':'พระปริยัติธรรม','BPP':'ตชด.','SPECIAL':'การศึกษาพิเศษ','HIGHER':'อุดมศึกษา','NURSERY':'สถานรับเลี้ยงเด็ก/ศพด.'};
    var counter={};
    for (var ai=0;ai<agKeys.length;ai++) { counter[agKeys[ai]]={};
      for (var fi=0;fi<forms.length;fi++) { var f=forms[fi]; if (f.agencyId==='ALL'||f.agencyId===agKeys[ai]) counter[agKeys[ai]][f.formId]={ formName:f.formName, s:null, ts:null, p:0, a:0, r:0 }; }
    }
    var timeline=[];
    for (var di=1;di<dataRows.length;di++) {
      var row=dataRows[di]; if (!row[0]) continue;
      var ag=String(row[2]),fid=String(row[3]),st=String(row[5]),ts=row[1];
      if (counter[ag]&&counter[ag][fid]) { var c=counter[ag][fid]; if (st==='รออนุมัติ')c.p++; if (st==='อนุมัติแล้ว')c.a++; if (st==='ส่งกลับแก้ไข')c.r++; if (!c.ts||ts>c.ts){c.ts=ts;c.s=st;} }
      if (timeline.length<20) timeline.push({ id:String(row[0]), timestamp:String(row[1]), agencyId:ag, agencyName:agNames[ag]||ag, title:String(row[4]), status:st, comment:String(row[9]||'') });
    }
    timeline.reverse();
    var agencySummary=[], tTotal=0, tApp=0, tPend=0, tRej=0, tNone=0;
    for (var si=0;si<agKeys.length;si++) {
      var aid=agKeys[si], fids=Object.keys(counter[aid]);
      var totalForms=fids.length, submitted=0, approved=0, pending=0, rejected=0, formList=[];
      for (var fli=0;fli<fids.length;fli++) { var fid2=fids[fli], c2=counter[aid][fid2];
        if (c2.s!==null)submitted++; if (c2.s==='อนุมัติแล้ว')approved++; if (c2.s==='รออนุมัติ')pending++; if (c2.s==='ส่งกลับแก้ไข')rejected++;
        formList.push({ formId:fid2, formName:c2.formName, latestStatus:c2.s, latestTimestamp:c2.ts?String(c2.ts):null, pending:c2.p, approved:c2.a, rejected:c2.r });
      }
      var notSent=totalForms-submitted, pct=totalForms>0?Math.round(approved/totalForms*100):0;
      tTotal+=totalForms; tApp+=approved; tPend+=pending; tRej+=rejected; tNone+=notSent;
      agencySummary.push({ agencyId:aid, agencyName:agNames[aid], totalForms:totalForms, submitted:submitted, approved:approved, pending:pending, rejected:rejected, notSent:notSent, completionPct:pct, forms:formList });
    }
    var result = { agencySummary:agencySummary,
      overall:{ allAgencies:agKeys.length, totalForms:tTotal, totalApproved:tApp, totalPending:tPend, totalRejected:tRej, totalNotSent:tNone, overallPct:tTotal>0?Math.round(tApp/tTotal*100):0 },
      timeline:timeline, generatedAt:Utilities.formatDate(new Date(),'Asia/Bangkok','dd/MM/yyyy HH:mm:ss'),
      _fromCache:false };
    _cacheSet(CACHE_KEY, result, CACHE_TTL.MONITORING);
    return result;
  } catch(err) {
    logAction('ERROR','getMonitoringData',err.toString());
    return { agencySummary:[], timeline:[], overall:{ allAgencies:13, totalForms:0, totalApproved:0, totalPending:0, totalRejected:0, totalNotSent:0, overallPct:0 }, generatedAt:Utilities.formatDate(new Date(),'Asia/Bangkok','dd/MM/yyyy HH:mm:ss'), _error:err.toString() };
  }
}

// ─────────────────────────────────────────────
// CACHE ADMIN
// ─────────────────────────────────────────────
function clearAllCache() {
  var keys = [
    'dashboard_all_all', 'monitoring_all', 'forms_all', 'settings_all',
    'gis_coords', 'users_list', 'yoy_data'
  ];
  ['all','2568','2567','2566'].forEach(function(y){
    ['all'].concat(Object.keys(AGENCY_MAP)).forEach(function(a){ keys.push('dashboard_'+y+'_'+a); });
  });
  Object.keys(AGENCY_MAP).forEach(function(k){ keys.push('forms_agency_'+k); });
  keys.push('forms_agency_ALL');
  _cacheInvalidate(keys);
  Logger.log('✅ ล้าง Cache ทั้งหมด ' + keys.length + ' keys เรียบร้อยแล้ว');
  return 'ล้าง Cache เรียบร้อยแล้ว';
}

function getCacheStatus() {
  var keys = ['dashboard_all_all','monitoring_all','forms_all','settings_all','gis_coords','users_list'];
  var status = {};
  var cache  = CacheService.getScriptCache();
  keys.forEach(function(k){
    var val = cache.get(k);
    status[k] = val ? 'HIT (' + Math.round(val.length/1024*10)/10 + 'KB)' : 'MISS';
  });
  Logger.log(JSON.stringify(status, null, 2));
  return status;
}

// ─────────────────────────────────────────────
// 12. REMINDER, EMAIL, SESSION LOG
// ─────────────────────────────────────────────
function sendReminderEmails(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'sendReminderEmails');
  if (!g.allowed) return g.error;
  try {
    var agencyIds=payload.agencyIds||[], formName=payload.formName||'รายงานสถิติ', sent=0;
    for (var ai=0;ai<agencyIds.length;ai++) {
      var agId=agencyIds[ai];
      if (!AGENCY_MAP[agId]) continue;
      var r = sendEmailNotification({ type:'deadline_reminder', agencyId:agId, formName:formName, userRole:auth.userRole });
      if (r && r.sent > 0) sent++;
    }
    return { success:true, message:'ส่งอีเมลแจ้งเตือน '+sent+' สังกัดเรียบร้อยแล้ว', sent:sent };
  } catch(e) {
    return { success:false, message:e.toString() };
  }
}

function debugMonitoringStep() {
  var result={ step:0, error:null };
  try {
    result.step=1; initSetup(); result.step=2;
    var ss=SpreadsheetApp.getActiveSpreadsheet(); result.step=3;
    var dS=ss.getSheetByName('Data'); result.dataSheetExists=!!dS; result.step=4;
    var dR=dS?dS.getDataRange().getValues():[]; result.dataRowCount=dR.length; result.step=5;
    var fS=ss.getSheetByName('FormTemplates'); result.formSheetExists=!!fS; result.step=6;
    result.agencyCount=Object.keys(AGENCY_MAP).length; result.step=7; result.success=true;
  } catch(e) { result.error=e.toString(); }
  return result;
}

function sendEmailNotification(payload) {
  try {
    var type=payload.type||'', agencyId=payload.agencyId||'', agencyName=payload.agencyName||AGENCY_MAP[agencyId]||agencyId;
    var formName=payload.formName||'', comment=payload.comment||'';
    var usersSheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var users=usersSheet?usersSheet.getDataRange().getValues():[], recipients=[];
    for (var i=1;i<users.length;i++) {
      if (users[i][4]===agencyId&&users[i][5]==='Active'&&users[i][6]) recipients.push(users[i][6]);
    }
    if (recipients.length===0) return { sent:0, message:'ไม่พบอีเมลผู้รับ' };
    var subject, bodyText, sysName='EduData Sakon — ระบบสารสนเทศด้านการศึกษา จังหวัดสกลนคร';
    var color = '#1a73e8';
    if (type==='approved') {
      subject='[อนุมัติแล้ว] '+formName+' — '+agencyName;
      bodyText='ข้อมูลแบบฟอร์ม <b>"'+formName+'"</b> ของหน่วยงาน <b>'+agencyName+'</b> ได้รับการอนุมัติเรียบร้อยแล้ว';
      color = '#1e8e3e';
    } else if (type==='rejected') {
      subject='[ส่งกลับแก้ไข] '+formName+' — '+agencyName;
      bodyText='ข้อมูล <b>"'+formName+'"</b> ถูกส่งกลับให้แก้ไข<br><br><b>เหตุผล:</b> <span style="color:#d93025;">'+(comment||'-')+'</span>';
      color = '#d93025';
    } else if (type==='received') {
      subject='[รับข้อมูลแล้ว] '+formName+' — '+agencyName;
      bodyText='ระบบได้รับข้อมูล <b>"'+formName+'"</b> จาก <b>'+agencyName+'</b> เรียบร้อยแล้ว อยู่ระหว่างรอการตรวจสอบและอนุมัติ';
      color = '#f9ab00';
    } else if (type==='deadline_reminder') {
      subject='[แจ้งเตือน] กำหนดส่งข้อมูล "'+formName+'" ใกล้ถึงแล้ว';
      bodyText='กรุณาดำเนินการส่งข้อมูล <b>"'+formName+'"</b> ภายในระยะเวลาที่กำหนด<br><br><b>หน่วยงาน:</b> '+agencyName;
      color = '#ea4335';
    } else return { sent:0, message:'ไม่รู้จัก type: '+type };
    var htmlBody = '<div style="font-family:\'Google Sans\',\'Sarabun\',sans-serif;max-width:600px;margin:0 auto;border:1px solid #dadce0;border-radius:8px;overflow:hidden;">'
      + '<div style="background-color:'+color+';padding:24px;text-align:center;color:#ffffff;"><h2 style="margin:0;font-size:20px;font-weight:500;">EduData Sakon</h2></div>'
      + '<div style="padding:32px 24px;background-color:#ffffff;color:#3c4043;line-height:1.6;font-size:14px;">'
      + '<p style="margin-top:0;">เรียน เจ้าหน้าที่ผู้รับผิดชอบ,</p><p>'+bodyText+'</p>'
      + '<p style="margin-top:32px;font-size:12px;color:#5f6368;border-top:1px solid #e8eaed;padding-top:16px;">ระบบแจ้งเตือนอัตโนมัติจาก '+sysName+'<br>* กรุณาอย่าตอบกลับอีเมลฉบับนี้</p>'
      + '</div></div>';
    var fullBody=bodyText.replace(/<[^>]*>?/gm,'')+'\n\n---\n'+sysName+'\nกรุณาอย่าตอบกลับอีเมลนี้';
    var sent=0;
    recipients.forEach(function(email){
      try { MailApp.sendEmail({ to:email, subject:subject, body:fullBody, htmlBody:htmlBody }); sent++; }
      catch(e) { logAction('SYSTEM','Email Error','ส่ง email ไม่ได้: '+email+' — '+e.toString()); }
    });
    logAction(payload.userRole||'SYSTEM','Send Email',type+' → '+agencyName+' ('+sent+' emails)');
    return { sent:sent, message:'ส่งอีเมลแล้ว '+sent+' ฉบับ' };
  } catch(e) {
    logAction('SYSTEM','Email Error',e.toString());
    return { sent:0, message:e.toString() };
  }
}

function sendDeadlineReminders() {
  try {
    initSetup();
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var formSheet=ss.getSheetByName('FormTemplates');
    if (!formSheet) return;
    var fRows=formSheet.getDataRange().getValues();
    var today=new Date(); today.setHours(0,0,0,0);
    for (var i=1;i<fRows.length;i++) {
      if (!fRows[i][0]||!fRows[i][4]) continue;
      var dlStr=String(fRows[i][4]);
      if (!dlStr.match(/^\d{4}-\d{2}-\d{2}$/)) continue;
      var dlDate=new Date(dlStr); dlDate.setHours(0,0,0,0);
      var diffDay=Math.round((dlDate-today)/86400000);
      if (diffDay===7||diffDay===3||diffDay===1) {
        var agencyId=String(fRows[i][2]);
        var agIds = agencyId==='ALL' ? Object.keys(AGENCY_MAP) : agencyId.split(',').map(function(s){ return s.trim(); });
        agIds.forEach(function(ag){
          sendEmailNotification({ type:'deadline_reminder', agencyId:ag, formName:String(fRows[i][1]), userRole:'SYSTEM' });
        });
      }
    }
    logAction('SYSTEM','Deadline Reminder','รัน sendDeadlineReminders เรียบร้อย');
  } catch(e) { logAction('SYSTEM','Deadline Reminder Error',e.toString()); }
}

function setupDailyTrigger() {
  ScriptApp.getProjectTriggers().forEach(function(t){
    if (t.getHandlerFunction()==='sendDeadlineReminders') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('sendDeadlineReminders').timeBased().everyDays(1).atHour(8).create();
  return 'ตั้ง Daily Trigger เรียบร้อยแล้ว (รันทุกวัน 08:00)';
}

function getSessionLog(payloadOrRole) {
  var auth = _resolveAuthParam(payloadOrRole); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getSessionLog');
  if (!g.allowed) return [];
  try {
    initSetup();
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AuditLogs');
    if (!sheet) return [];
    var data=sheet.getDataRange().getDisplayValues(), result=[], sessions={};
    for (var i=1;i<data.length;i++) {
      var ts=String(data[i][0]||''), role=String(data[i][1]||''), action=String(data[i][2]||''), detail=String(data[i][3]||'');
      if (!ts||['LOGIN','LOGIN_FAILED','LOGOUT'].indexOf(action)===-1) continue;
      var uMatch=detail.match(/user:([^\s|]+)/), nmMatch=detail.match(/name:([^|]+)/), agMatch=detail.match(/agency:([^|]+)/);
      var uname=uMatch?uMatch[1].trim():detail.split(' ')[0], agId=agMatch?agMatch[1].trim():'';
      if (action==='LOGIN') sessions[uname]=ts;
      else if (action==='LOGOUT'&&sessions[uname]) delete sessions[uname];
      if (result.length<200) {
        result.unshift({ timestamp:ts, username:uname, role:role, agencyName:AGENCY_MAP[agId]||agId||uname, action:action, duration:'-', detail:detail.replace(/user:[^\s|]+\s*\|?\s*/,'').replace(/name:[^|]+\|?\s*/,'').trim()||action });
      }
    }
    return result.slice(0,150);
  } catch(e) { return []; }
}

function fixDataSheetHeader() {
  var ss=SpreadsheetApp.getActiveSpreadsheet(), sheet=ss.getSheetByName('Data');
  if (!sheet) { Logger.log('ไม่พบ Data sheet'); return; }
  var correct=['ID','Timestamp','AgencyID','FormID','ReportTitle','Status','Lat','Lng','RawDataJSON','AdminComment'];
  var current=sheet.getRange(1,1,1,10).getValues()[0], mismatch=false;
  for (var i=0;i<correct.length;i++) { if (String(current[i]||'')!==correct[i]) { mismatch=true; break; } }
  if (!mismatch) { Logger.log('✅ Header ถูกต้องทั้งหมด'); return; }
  sheet.getRange(1,1,1,correct.length).setValues([correct]).setFontWeight('bold').setBackground('#f1f3f4');
  sheet.setFrozenRows(1);
  Logger.log('✅ แก้ header เรียบร้อยแล้ว');
}

function verifySession(token) {
  if (!token) return { valid: false };
  var sess = _resolveSession(token);
  if (!sess) return { valid: false };
  // ตรวจสอบว่า user ยังคง Active อยู่ใน Sheet
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    var data  = sheet ? sheet.getDataRange().getValues() : [];
    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]).toLowerCase() === sess.username) {
        if (String(data[i][5]) !== 'Active') return { valid: false };
        return { valid: true, userData: { role: sess.role, name: sess.name, agencyId: sess.agencyId, agency: AGENCY_MAP[sess.agencyId] || sess.agencyId } };
      }
    }
  } catch(e) {}
  return { valid: true, userData: { role: sess.role, name: sess.name, agencyId: sess.agencyId, agency: AGENCY_MAP[sess.agencyId] || sess.agencyId } };
}

function fixFormTemplatesHeader() {
  var ss=SpreadsheetApp.getActiveSpreadsheet(), sheet=ss.getSheetByName('FormTemplates');
  if (!sheet) { Logger.log('ไม่พบ FormTemplates sheet'); return; }
  var correct=['FormID','FormName','AgencyID','FormJSON','Deadline'];
  var current=sheet.getRange(1,1,1,5).getValues()[0], mismatch=false;
  for (var i=0;i<correct.length;i++) { if (String(current[i]||'')!==correct[i]) { mismatch=true; break; } }
  if (!mismatch) { Logger.log('✅ Header ถูกต้องแล้ว'); return; }
  sheet.getRange(1,1,1,correct.length).setValues([correct]).setFontWeight('bold').setBackground('#f1f3f4');
  sheet.setFrozenRows(1);
  Logger.log('✅ แก้ header เรียบร้อยแล้ว');
}

// ─────────────────────────────────────────────
// DEADLINE NOTIFICATIONS — ดึงแบบฟอร์มที่ใกล้ Deadline สำหรับ user นั้นๆ
// ─────────────────────────────────────────────
function getUpcomingDeadlines(payload) {
  var auth = _resolveAuth(payload);
  if (auth.error) return { success: false, items: [] };
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('FormTemplates');
    if (!sheet) return { success: true, items: [] };
    var rows  = sheet.getDataRange().getValues();
    var today = new Date(); today.setHours(0, 0, 0, 0);
    var items = [];
    for (var i = 1; i < rows.length; i++) {
      var formId   = String(rows[i][0] || '');
      var formName = String(rows[i][1] || '');
      var agencyId = String(rows[i][2] || '');
      var dlStr    = String(rows[i][4] || '');
      if (!formId || !dlStr.match(/^\d{4}-\d{2}-\d{2}$/)) continue;
      // ตรวจสิทธิ์: admin เห็นทุกสังกัด, agency เห็นเฉพาะของตัวเอง
      if (!IS_ADMIN_UP(auth.userRole)) {
        var allowed = agencyId === 'ALL' ||
          agencyId.split(',').map(function(s){ return s.trim(); }).indexOf(auth.agencyId) >= 0;
        if (!allowed) continue;
      }
      var dlDate = new Date(dlStr); dlDate.setHours(0, 0, 0, 0);
      var diffDay = Math.round((dlDate - today) / 86400000);
      if (diffDay >= 0 && diffDay <= 14) { // แจ้งเตือนล่วงหน้า 14 วัน
        items.push({
          formId:   formId,
          formName: formName,
          deadline: dlStr,
          daysLeft: diffDay,
          urgent:   diffDay <= 3,
          agencies: agencyId
        });
      }
    }
    // เรียงจาก deadline ใกล้ที่สุดก่อน
    items.sort(function(a, b){ return a.daysLeft - b.daysLeft; });
    return { success: true, items: items };
  } catch(e) {
    return { success: false, items: [], message: e.toString() };
  }
}

// ─────────────────────────────────────────────
// 13. AI BI PROMPT ANALYZER
// ─────────────────────────────────────────────
function processAiBiPrompt(payload) {
  var auth = _resolveAuth(payload);
  if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_AGENCY_UP, 'processAiBiPrompt');
  if (!g.allowed) return g.error;

  var apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) return { success: false, message: 'ไม่พบ GEMINI_API_KEY ใน Script Properties' };

  var prompt = payload.prompt;
  
  var systemInstruction = 'คุณคือผู้เชี่ยวชาญ AI สำหรับตั้งค่าระบบ Business Intelligence (BI Dashboard) ให้ศึกษาธิการจังหวัดสกลนคร ' +
    'หน้าที่ของคุณคือการแปลงคำสั่งภาษาไทยของผู้ใช้ให้เป็นโครงสร้าง JSON เพื่อสร้าง Widget บนหน้าแดชบอร์ดลากวาง\n\n' +
    '-- ข้อมูลตารางสถิติและคีย์ที่ระบบรองรับ (dataKey):\n' +
    '1. "totalSchools" - จำนวนสถานศึกษาทั้งหมดแยกรายสังกัด (เหมาะกับ KPI, Bar, Pie)\n' +
    '2. "totalStudents" - จำนวนผู้เรียนรวมทั้งจังหวัด (เหมาะกับ KPI)\n' +
    '3. "totalTeachers" - จำนวนครูและบุคลากรรวมทั้งจังหวัด (เหมาะกับ KPI)\n' +
    '4. "totalSpecial" - จำนวนนักเรียนความต้องการพิเศษรวมทั้งจังหวัด (เหมาะกับ KPI)\n' +
    '5. "chart_agency" - สถิติจำนวนสถานศึกษาแยกตามสังกัด (เหมาะกับ Bar, Pie, Donut)\n' +
    '6. "student_all_levels" - สถิติผู้เรียนแยกตามระดับการศึกษา (ก่อนประถม, ประถม, ม.ต้น, ม.ปลาย, ปวช/ปวส) (เหมาะกับ Bar, Pie, Radar)\n' +
    '7. "teacher_by_agency" - สถิติจำนวนครูและบุคลากรแยกตามสังกัด (เหมาะกับ Bar, Line, Pie)\n' +
    '8. "special_all" - สถิตินักเรียนที่มีความต้องการพิเศษจำแนกรายโรค (ออทิสติก, ร่างกาย, สติปัญญา) (เหมาะกับ Bar, Pie)\n' +
    '9. "mon_pct" - อัตราเปอร์เซ็นต์ความครบถ้วนในการส่งข้อมูลภาพรวม (เหมาะกับ Gauge, Progress Bar)\n\n' +
    '-- รูปแบบ Widget ที่ระบบรองรับ (type):\n' +
    '- "kpi": การ์ดแสดงผลตัวเลขเด่นหลักเดียว\n' +
    '- "bar": กราฟแท่งแนวตั้ง (เหมาะกับการเปรียบเทียบข้อมูลจำแนกกลุ่ม)\n' +
    '- "bar_h": กราฟแท่งแนวนอน\n' +
    '- "line": กราฟเส้นแสดงแนวโน้ม\n' +
    '- "pie": กราฟวงกลม\n' +
    '- "donut": กราฟโดนัท\n' +
    '- "radar": กราฟใยแมงมุม (เหมาะกับข้อมูลหลายมิติ เช่น student_all_levels)\n' +
    '- "progress": แถบความคืบหน้า\n' +
    '- "gauge": เกจวัดความเร็ว/Speedometer\n\n' +
    '-- ข้อกำหนดการส่งออก JSON:\n' +
    'จงส่งออกคำตอบเป็น JSON Object บรรทัดเดียวเท่านั้น ห้ามมีคำอธิบายอื่นนอกเหนือจาก JSON ห้ามใส่ Markdown Fenced Blocks (เช่น ```json) คีย์ใน JSON ต้องตรงตามเงื่อนไขดังนี้:\n' +
    '{\n' +
    '  "type": "ประเภทของ widget",\n' +
    '  "title": "ชื่อหัวข้อกราฟหรือตัวเลขภาษาไทยที่ตรงใจความและสวยงาม",\n' +
    '  "dataKey": "คีย์ข้อมูล (เลือกจาก 1-9 ด้านบนที่แมตช์ที่สุด)",\n' +
    '  "cols": "ความกว้างของคอลัมน์ (ตัวเลข 1 ถึง 12: kpi/gauge/donut/pie ควรได้ 3-4, กราฟอื่นๆ ควรได้ 6, ตารางควรได้ 12)",\n' +
    '  "color": "สีเด่นประจำกราฟเป็นรหัส Hex (เช่น #1a73e8 สำหรับสีน้ำเงิน, #34a853 สำหรับสีเขียว, #fbbc04 สำหรับเหลือง, #ea4335 สำหรับแดง, #673ab7 สำหรับม่วง)",\n' +
    '  "showLegend": true,\n' +
    '  "showLabel": true\n' +
    '}';

  var contents = [
    { role: 'user', parts: [{ text: 'คำสั่งผู้ใช้: "ขอดูกราฟวงกลมสัดส่วนนักเรียนแยกตามระดับชั้นด้วยครับ"' }] },
    { role: 'model', parts: [{ text: '{"type":"pie","title":"สัดส่วนผู้เรียนแยกตามระดับชั้น","dataKey":"student_all_levels","cols":4,"color":"#ea4335","showLegend":true,"showLabel":true}' }] },
    { role: 'user', parts: [{ text: 'คำสั่งผู้ใช้: "ขอตัวเลขครูทั้งหมดทั้งจังหวัดแบบตัวหนาและมีเกจวัดความคืบหน้า"' }] },
    { role: 'model', parts: [{ text: '{"type":"gauge","title":"ความคืบหน้าการส่งข้อมูลภาพรวมจังหวัด","dataKey":"mon_pct","cols":4,"color":"#1a73e8","showLegend":false,"showLabel":true}' }] },
    { role: 'user', parts: [{ text: 'คำสั่งผู้ใช้: "' + prompt + '"' }] }
  ];

  try {
    var result = _callGemini(apiKey, contents, 1024, 0.2, systemInstruction);
    if (!result.ok) return { success: false, message: result.error };
    
    var txt = result.text.trim();
    if (txt.indexOf('```') !== -1) {
      txt = txt.replace(/```json/gi, '').replace(/```/g, '').trim();
    }
    
    var widgetDef = JSON.parse(txt);
    return {
      success: true,
      widget: widgetDef,
      modelUsed: result.model
    };
  } catch(e) {
    return { success: false, message: 'การวิเคราะห์ล้มเหลว: ' + e.toString() };
  }
}


// ─────────────────────────────────────────────
// 15. MONITORING MANAGEMENT ACTIONS
// ─────────────────────────────────────────────

// 15A. ดึง Audit Log กรองตาม agencyId
function getAgencyAuditLog(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getAgencyAuditLog');
  if (!g.allowed) return g.error;

  var agencyId   = payload.agencyId  || '';
  var agencyName = AGENCY_MAP[agencyId] || agencyId;
  var maxRows    = payload.maxRows || 60;

  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AuditLogs');
    if (!sheet) return { success: true, logs: [], agencyName: agencyName };

    var data = sheet.getDataRange().getValues();
    var logs = [];
    for (var i = data.length - 1; i >= 1; i--) {
      var row = data[i];
      if (!row[0]) continue;
      var detail = String(row[3] || '');
      if (agencyId && detail.indexOf(agencyId) === -1 && detail.indexOf(agencyName) === -1) continue;
      var ts = row[0];
      var tsStr = Object.prototype.toString.call(ts) === '[object Date]'
        ? Utilities.formatDate(ts, 'GMT+7', 'dd/MM/yyyy HH:mm:ss')
        : String(ts || '');
      logs.push({ timestamp: tsStr, role: String(row[1]||''), action: String(row[2]||''), detail: detail });
      if (logs.length >= maxRows) break;
    }
    return { success: true, logs: logs, agencyName: agencyName };
  } catch(e) {
    return { success: false, message: e.toString() };
  }
}

// 15B. Bulk Approve หรือ Reject ฟอร์มที่รออนุมัติทั้งหมดของสังกัดนี้
function bulkApproveReject(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'bulkApproveReject');
  if (!g.allowed) return g.error;

  var agencyId   = payload.agencyId || '';
  var action     = payload.action   || 'อนุมัติแล้ว';
  var comment    = payload.comment  || '';
  var agencyName = AGENCY_MAP[agencyId] || agencyId;

  if (!agencyId) return { success: false, message: 'ไม่พบรหัสสังกัด' };
  if (action !== 'อนุมัติแล้ว' && action !== 'ส่งกลับแก้ไข') {
    return { success: false, message: 'action ต้องเป็น "อนุมัติแล้ว" หรือ "ส่งกลับแก้ไข" เท่านั้น' };
  }

  var lock = LockService.getScriptLock();
  try { lock.waitLock(30000); } catch(e) {
    return { success: false, message: 'ระบบหนาแน่น กรุณาลองใหม่' };
  }
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data');
    if (!sheet) return { success: false, message: 'ไม่พบแผ่นงาน Data' };
    var data  = sheet.getDataRange().getValues();
    var count = 0;
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][2]||'').trim() === agencyId && String(data[i][5]||'').trim() === 'รออนุมัติ') {
        sheet.getRange(i+1, 6).setValue(action);
        if (comment) sheet.getRange(i+1, 10).setValue(comment);
        count++;
      }
    }
    if (count === 0) return { success: false, message: 'ไม่พบฟอร์มที่มีสถานะ "รออนุมัติ" ของสังกัดนี้' };
    _invalidateDashboardCache();
    logAction(auth.userRole, 'Bulk '+action, agencyName+' — '+count+' ฟอร์ม'+(comment?' เหตุผล: '+comment:''));
    return { success: true, count: count, message: (action==='อนุมัติแล้ว'?'อนุมัติ':'ส่งกลับ')+' สำเร็จ '+count+' ฟอร์ม' };
  } catch(e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

// 15C. Export ข้อมูลของสังกัดเป็น CSV
function exportAgencyDataCSV(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'exportAgencyDataCSV');
  if (!g.allowed) return g.error;

  var agencyId   = payload.agencyId || '';
  var agencyName = AGENCY_MAP[agencyId] || agencyId;
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data');
    if (!sheet) return { success: false, message: 'ไม่พบแผ่นงาน Data' };
    var data = sheet.getDataRange().getValues();
    var headers = ['"ID"','"วันเวลา"','"รหัสสังกัด"','"ชื่อสังกัด"','"รหัสฟอร์ม"','"ชื่อรายงาน"','"สถานะ"','"หมายเหตุ Admin"'];
    var rows = [headers.join(',')];
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row[0]) continue;
      var rowAgency = String(row[2]||'').trim();
      if (agencyId && rowAgency !== agencyId) continue;
      var ts = row[1];
      var tsStr = Object.prototype.toString.call(ts) === '[object Date]'
        ? Utilities.formatDate(ts,'GMT+7','dd/MM/yyyy HH:mm:ss') : String(ts||'');
      rows.push([
        '"'+String(row[0]||'').replace(/"/g,'""')+'"',
        '"'+tsStr.replace(/"/g,'""')+'"',
        '"'+rowAgency.replace(/"/g,'""')+'"',
        '"'+(AGENCY_MAP[rowAgency]||rowAgency).replace(/"/g,'""')+'"',
        '"'+String(row[3]||'').replace(/"/g,'""')+'"',
        '"'+String(row[4]||'').replace(/"/g,'""')+'"',
        '"'+String(row[5]||'').replace(/"/g,'""')+'"',
        '"'+String(row[9]||'').replace(/"/g,'""')+'"'
      ].join(','));
    }
    var csv = rows.join('\n');
    var filename = 'EduStat_'+agencyId+'_'+Utilities.formatDate(new Date(),'GMT+7','yyyyMMdd')+'.csv';
    logAction(auth.userRole,'Export CSV', agencyName+' — '+(rows.length-1)+' แถว');
    return { success: true, csv: csv, filename: filename, rowCount: rows.length-1, agencyName: agencyName };
  } catch(e) {
    return { success: false, message: e.toString() };
  }
}

// 15D. ส่งอีเมลแจ้งเตือนสำเร็จรูป (เทมเพลตตายตัว ไม่ใช้ AI)
function sendSimpleReminderEmail(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'sendSimpleReminderEmail');
  if (!g.allowed) return g.error;

  var agencyId   = payload.agencyId   || '';
  var agencyName = AGENCY_MAP[agencyId] || agencyId;
  var recipients = payload.recipients  || [];
  var customNote = payload.customNote  || '';

  if (!agencyId) return { success: false, message: 'ไม่พบรหัสสังกัด' };

  if (recipients.length === 0) {
    var usersSheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Users');
    if (usersSheet) {
      var users = usersSheet.getDataRange().getValues();
      for (var ui = 1; ui < users.length; ui++) {
        if (String(users[ui][4]).trim()===agencyId && String(users[ui][5]).trim()==='Active' && users[ui][6]) {
          recipients.push(String(users[ui][6]).trim());
        }
      }
    }
  }
  if (recipients.length === 0) {
    return { success: false, message: 'ไม่พบอีเมลผู้รับของสังกัดนี้ กรุณาเพิ่มอีเมลในระบบจัดการผู้ใช้ก่อน' };
  }

  var today   = Utilities.formatDate(new Date(),'GMT+7','dd/MM/yyyy');
  var subject = '[แจ้งเตือน] ขอความร่วมมือนำส่งข้อมูลสถิติ — '+agencyName;
  var bodyText = 'เรียน เจ้าหน้าที่ผู้รับผิดชอบ '+agencyName+'\n\n'+
    'ตามที่ศึกษาธิการจังหวัดสกลนครได้เปิดระบบสารสนเทศด้านการศึกษา (EduData Sakon) ขอความกรุณาดำเนินการนำส่งข้อมูลสถิติและรายงานที่ค้างส่งให้ครบถ้วนภายในระยะเวลาที่กำหนด\n\n'+
    (customNote ? 'หมายเหตุ: '+customNote+'\n\n' : '')+
    'เข้าสู่ระบบ: https://script.google.com/macros/s/AKfycbwXzHXU0JUbdMQlkCa7zkWrWN2hWbai6cCFaU8-JzygE3BYviI19-_NQPzG9396RDF-Ug/exec\n\n'+
    'ศึกษาธิการจังหวัดสกลนคร | '+today;

  var bodyHtml =
    '<div style="font-family:\'Sarabun\',sans-serif;max-width:580px;margin:0 auto;border:1px solid #dadce0;border-radius:10px;overflow:hidden;">'+
    '<div style="background:#1a237e;padding:18px 24px;display:flex;align-items:center;gap:10px;">'+
    '<span style="background:white;border-radius:6px;padding:4px 10px;font-weight:700;color:#1a237e;font-size:15px;">EduData Sakon</span>'+
    '<span style="color:rgba(255,255,255,0.8);font-size:12px;">ระบบสารสนเทศด้านการศึกษา จ.สกลนคร</span></div>'+
    '<div style="padding:28px 24px;background:#fff;color:#212121;line-height:1.8;font-size:14px;">'+
    '<p>เรียน เจ้าหน้าที่ผู้รับผิดชอบ <strong>'+agencyName+'</strong></p>'+
    '<p>ตามที่ศึกษาธิการจังหวัดสกลนครได้เปิดระบบสารสนเทศด้านการศึกษา <strong>EduData Sakon</strong> ขอความกรุณาท่านดำเนินการ<strong>นำส่งข้อมูลสถิติและรายงานที่ค้างส่ง</strong>ให้ครบถ้วนภายในระยะเวลาที่กำหนด</p>'+
    (customNote ? '<div style="background:#fff8e1;border-left:4px solid #f59e0b;padding:12px 16px;margin:16px 0;border-radius:0 6px 6px 0;"><strong>📌 หมายเหตุ:</strong> '+customNote+'</div>' : '')+
    '<p style="margin:20px 0;"><a href="https://script.google.com/macros/s/AKfycbwXzHXU0JUbdMQlkCa7zkWrWN2hWbai6cCFaU8-JzygE3BYviI19-_NQPzG9396RDF-Ug/exec" style="background:#1a237e;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">🔗 เข้าสู่ระบบ EduData Sakon</a></p>'+
    '<p style="margin-top:24px;">ขอแสดงความนับถือ<br><strong>ศึกษาธิการจังหวัดสกลนคร</strong><br><span style="color:#666;">'+today+'</span></p>'+
    '</div>'+
    '<div style="background:#f5f5f5;padding:10px 24px;font-size:11px;color:#9e9e9e;text-align:center;">อีเมลแจ้งเตือนอัตโนมัติจาก EduData Sakon — กรุณาอย่าตอบกลับ</div></div>';

  var sentCount = 0;
  var errors = [];
  recipients.forEach(function(email) {
    try { MailApp.sendEmail({ to: email, subject: subject, body: bodyText, htmlBody: bodyHtml }); sentCount++; }
    catch(e) { errors.push(email+': '+e.toString()); }
  });

  logAction(auth.userRole,'Send Reminder Email', agencyName+' — '+sentCount+'/'+recipients.length+' ฉบับ');
  if (sentCount === 0) return { success: false, message: 'ส่งอีเมลไม่สำเร็จ: '+errors.join(', ') };
  return { success: true, message: 'ส่งอีเมลแจ้งเตือนสำเร็จ '+sentCount+' ฉบับ', sentCount: sentCount };
}



function sendExecutiveBriefingEmail(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_ADMIN_UP, 'sendExecutiveBriefingEmail');
  if (!g.allowed) return g.error;
  
  try {
    var recipient = payload.recipient;
    var subject = payload.subject || 'รายงานสรุปเชิงนโยบายสำหรับผู้บริหาร (Executive Briefing Pack) — จังหวัดสกลนคร';
    var htmlContent = payload.htmlContent;
    
    if (!recipient) {
      return { success: false, message: 'กรุณาระบุอีเมลผู้รับปลายทาง' };
    }
    if (!htmlContent) {
      return { success: false, message: 'เนื้อหารายงานห้ามว่าง' };
    }
    
    // Send email
    MailApp.sendEmail({
      to: recipient.trim(),
      subject: subject,
      body: 'โปรดเปิดอีเมลนี้ด้วยโปรแกรมที่รองรับการแสดงผลแบบ HTML เพื่อดูรายงานสรุปเชิงนโยบาย',
      htmlBody: htmlContent
    });
    
    logAction(auth.userRole, 'Send Executive Briefing', 'ส่งรายงานสรุปให้ผู้บริหารอีเมล: ' + recipient);
    return { success: true, message: 'ส่งรายงานให้ผู้บริหารสำเร็จแล้ว' };
  } catch(e) {
    logAction('SYSTEM', 'Executive Briefing Email Error', e.toString());
    return { success: false, message: e.toString() };
  }
}

// ─────────────────────────────────────────────
// 24. PREDICTIVE AI FORECASTING
// ─────────────────────────────────────────────
function getPredictiveForecastData(payload) {
  var auth = _resolveAuth(payload); if (auth.error) return auth.error;
  var g = checkRole(auth.userRole, IS_AGENCY_UP, 'getPredictiveForecastData');
  if (!g.allowed) return g.error;
  
  var apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) return { success: false, message: 'ไม่พบ GEMINI_API_KEY ใน Script Properties' };
  
  initSetup();
  var ss    = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Data');
  if (!sheet) return { success: false, message: 'ไม่พบตารางข้อมูล Data' };
  
  var data  = sheet.getDataRange().getValues();
  var yearlyData = {};
  
  for (var i = 1; i < data.length; i++) {
    var status = data[i][5];
    var rowAgency = data[i][2];
    var rawJson = data[i][8];
    if (status !== 'อนุมัติแล้ว' || !rawJson) continue;
    
    var ts = data[i][1];
    var yr = '';
    if (ts instanceof Date) {
      yr = String(ts.getFullYear() + 543);
    } else {
      var ym = String(ts).match(/\d{2}\/\d{2}\/(\d{4})/) || String(ts).match(/(\d{4})-\d{2}-\d{2}/);
      if (ym) { 
        var y = parseInt(ym[1]); 
        yr = String(y > 2500 ? y : y + 543); 
      }
    }
    if (!yr) continue;
    
    try {
      var fd = JSON.parse(rawJson);
      var sch = Number(fd.school_total || 0);
      var std = Number(fd.student_total || 0);
      var tch = Number(fd.teacher_total || 0);
      
      if (!yearlyData[yr]) {
        yearlyData[yr] = { student_total: 0, teacher_total: 0, school_total: 0 };
      }
      yearlyData[yr].student_total += std;
      yearlyData[yr].teacher_total += tch;
      yearlyData[yr].school_total += sch;
    } catch(e) {}
  }
  
  var historySummary = [];
  var sortedYears = Object.keys(yearlyData).sort();
  sortedYears.forEach(function(yr) {
    historySummary.push({
      year: yr,
      student_total: yearlyData[yr].student_total,
      teacher_total: yearlyData[yr].teacher_total,
      school_total: yearlyData[yr].school_total
    });
  });
  
  // Fallback mock if data is scarce in spreadsheet
  if (historySummary.length === 0) {
    historySummary = [
      { year: "2567", student_total: 82450, teacher_total: 4120, school_total: 120 },
      { year: "2568", student_total: 81200, teacher_total: 4050, school_total: 120 },
      { year: "2569", student_total: 80100, teacher_total: 3980, school_total: 120 }
    ];
  }
  
  var systemPrompt = "คุณเป็นผู้เชี่ยวชาญด้านวิเคราะห์สถิติและทำนายแนวโน้มทางการศึกษา (Educational Predictive Analyst) ของกระทรวงศึกษาธิการ ประเทศไทย\n" +
                     "ภารกิจ: วิเคราะห์สถิติจำนวนนักเรียน, จำนวนครู, จำนวนโรงเรียนย้อนหลังของจังหวัดสกลนคร แล้วคาดการณ์ (Forecast) อีก 3 ปีการศึกษาข้างหน้า (เช่น ปี 2570, 2571, 2572) และเขียนวิเคราะห์ข้อเสนอแนะเชิงนโยบาย\n" +
                     "ข้อมูลป้อนเข้าย้อนหลัง:\n" + JSON.stringify(historySummary) + "\n\n" +
                     "คุณต้องให้ผลลัพธ์ในรูปแบบ JSON เท่านั้น ห้ามเขียนคำนำ ห้ามเขียนมาร์กดาวน์อื่นใดนอกเหนือจากเนื้อหา JSON โครงสร้าง JSON ที่ต้องการมีดังนี้:\n" +
                     "{\n" +
                     "  \"predictions\": [\n" +
                     "    { \"year\": \"2570\", \"student_total\": 79000, \"teacher_total\": 3920, \"school_total\": 120 },\n" +
                     "    { \"year\": \"2571\", \"student_total\": 78100, \"teacher_total\": 3860, \"school_total\": 120 },\n" +
                     "    { \"year\": \"2572\", \"student_total\": 77200, \"teacher_total\": 3800, \"school_total\": 120 }\n" +
                     "  ],\n" +
                     "  \"analysis\": \"สรุปข้อวิเคราะห์เชิงนโยบายภาษาไทยอย่างละเอียดสำหรับผู้บริหาร เช่น อัตราการลดลงของจำนวนผู้เรียน ปัญหาความขาดแคลนครูต่อห้องเรียน และคำแนะนำการควบรวมสถานศึกษาหรือจัดสรรอัตรากำลังโดยใช้ข้อมูลตัวเลขยืนยัน (เขียนเป็น Bullet Points ประมาณ 3-4 ข้อ)\"\n" +
                     "}";
                     
  var userContent = [{ role: 'user', parts: [{ text: "โปรดคำนวณและตอบกลับมาเป็น JSON ตามรูปแบบที่ระบุไว้เท่านั้น" }] }];
  
  var response = _callGemini(apiKey, userContent, 2048, 0.2, systemPrompt);
  if (!response.success) {
    return { success: false, message: 'Gemini API Error: ' + response.message };
  }
  
  try {
    var rawText = response.text.trim();
    if (rawText.indexOf("```json") === 0) {
      rawText = rawText.substring(7, rawText.length - 3).trim();
    } else if (rawText.indexOf("```") === 0) {
      rawText = rawText.substring(3, rawText.length - 3).trim();
    }
    
    var forecast = JSON.parse(rawText);
    logAction(auth.userRole, 'Run Predictive AI', 'รันระบบคาดการณ์สถิติและทำนายแนวโน้ม 3 ปีล่วงหน้า');
    return { success: true, history: historySummary, forecast: forecast.predictions, analysis: forecast.analysis };
  } catch(e) {
    return { success: false, message: 'ไม่สามารถแยกวิเคราะห์ผลลัพธ์จาก AI: ' + e.toString() + ' (Raw: ' + response.text + ')' };
  }
}

/**
 * 🔐 ฟังก์ชันสำหรับผู้ใช้งานทั่วไปเปลี่ยนรหัสผ่านของตนเอง
 */
function changePassword(payload) {
  try {
    var auth = _resolveAuth(payload);
    if (auth.error) return auth.error;
    
    var username = auth.username;
    var currentPwd = payload.currentPassword ? payload.currentPassword.trim() : '';
    var newPwd = payload.newPassword ? payload.newPassword.trim() : '';
    
    if (!currentPwd || !newPwd) {
      return { success: false, message: 'กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่' };
    }
    
    if (newPwd.length < 8) {
      return { success: false, message: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร' };
    }
    
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Users');
    if (!sheet) return { success: false, message: 'ไม่พบตารางข้อมูลผู้ใช้งานในระบบ' };
    
    var data = sheet.getDataRange().getValues();
    var foundIndex = -1;
    
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').toLowerCase().trim() === username.toLowerCase()) {
        foundIndex = i;
        break;
      }
    }
    
    if (foundIndex === -1) {
      return { success: false, message: 'ไม่พบชื่อผู้ใช้งานในระบบ' };
    }
    
    // ตรวจสอบรหัสผ่านปัจจุบัน
    var stored = String(data[foundIndex][1] || '').trim();
    if (!_verifyPassword(currentPwd, stored)) {
      return { success: false, message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง' };
    }
    
    // บันทึกรหัสผ่านใหม่เข้ารหัส sha256
    var np = _encodePassword(newPwd);
    sheet.getRange(foundIndex + 1, 2).setValue(np);
    
    logAction(auth.userRole, 'Change Password Self', 'ผู้ใช้งานเปลี่ยนรหัสผ่านด้วยตนเอง: ' + username);
    _cacheInvalidate(['users_list']);
    
    return { success: true, message: 'เปลี่ยนรหัสผ่านใหม่เรียบร้อยแล้ว' };
  } catch(e) {
    return { success: false, message: 'เกิดข้อผิดพลาด: ' + e.toString() };
  }
}

/**
 * 📩 ฟังก์ชันสำหรับแจ้งปัญหาการใช้งานระบบจากหน้าล็อกอิน (ผู้ใช้ภายนอก/ทั่วไป)
 */
function submitSystemIssueBackend(payload) {
  try {
    var name = payload.name ? payload.name.trim() : '';
    var agency = payload.agency ? payload.agency.trim() : '';
    var contact = payload.contact ? payload.contact.trim() : '';
    var detail = payload.detail ? payload.detail.trim() : '';
    
    if (!name || !agency || !contact || !detail) {
      return { success: false, message: 'กรุณากรอกข้อมูลให้ครบถ้วนในทุกช่อง' };
    }
    
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Issues');
    if (!sheet) {
      sheet = ss.insertSheet('Issues');
      sheet.appendRow(['Timestamp', 'ReporterName', 'Agency', 'Contact', 'Detail', 'Status', 'ResolveComment']);
      sheet.getRange('A1:G1').setFontWeight('bold').setBackground('#fce8e6'); sheet.setFrozenRows(1);
    }
    
    // หากเป็นเบอร์โทรศัพท์ (มีเฉพาะตัวเลข) ให้ใส่ ' นำหน้าเพื่อบังคับ Google Sheets บันทึกเป็น Text ไม่ให้ตัดเลข 0
    var formattedContact = contact;
    if (/^\d+$/.test(contact)) {
      formattedContact = "'" + contact;
    }
    
    var timestamp = Utilities.formatDate(new Date(), "GMT+7", "dd/MM/yyyy HH:mm:ss");
    var row = [
      timestamp,
      name,
      agency,
      formattedContact,
      detail,
      'รอดำเนินการ',
      ''
    ];
    sheet.appendRow(row);
    
    logAction('GUEST', 'REPORT_ISSUE', 'ผู้แจ้ง: ' + name + ' | สังกัด: ' + agency);
    
    return { success: true, message: 'ส่งข้อมูลการแจ้งปัญหาเรียบร้อยแล้ว แอดมินจะดำเนินการสืบสวนและประสานงานโดยเร็วที่สุด' };
  } catch(e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล: ' + e.toString() };
  }
}

/**
 * 🔍 ฟังก์ชันสำหรับค้นหาติดตามประวัติสถานะการแจ้งปัญหาจากเบอร์โทรศัพท์/ช่องทางการติดต่อ หรือชื่อผู้แจ้ง
 */
function searchSystemIssuesBackend(queryStr) {
  try {
    if (!queryStr || queryStr.trim().length < 2) {
      return { success: false, message: 'กรุณากรอกคำค้นหาอย่างน้อย 2 ตัวอักษร' };
    }
    
    var searchKey = queryStr.toLowerCase().trim();
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Issues');
    if (!sheet) return { success: true, issues: [], message: 'ยังไม่มีประวัติการแจ้งปัญหาในระบบ' };
    
    var data = sheet.getDataRange().getValues();
    var results = [];
    
    // Headers: Timestamp (0), ReporterName (1), Agency (2), Contact (3), Detail (4), Status (5), ResolveComment (6)
    for (var i = 1; i < data.length; i++) {
      var reporter = String(data[i][1] || '').toLowerCase();
      var agency = String(data[i][2] || '').toLowerCase();
      
      var contactRaw = String(data[i][3] || '').trim();
      // หากโดน Google Sheets ตัดเลข 0 นำหน้า (เบอร์โทรศัพท์เหลือ 8-9 หลัก) ให้เติมเลข 0 กลับคืน
      if (/^\d{8,9}$/.test(contactRaw)) {
        contactRaw = '0' + contactRaw;
      }
      var contact = contactRaw.toLowerCase();
      
      // ค้นหาแบบบางส่วน (partial match)
      if (reporter.indexOf(searchKey) !== -1 || contact.indexOf(searchKey) !== -1 || agency.indexOf(searchKey) !== -1) {
        results.push({
          timestamp: String(data[i][0] || ''),
          reporterName: String(data[i][1] || ''),
          agency: String(data[i][2] || ''),
          contact: contactRaw,
          detail: String(data[i][4] || ''),
          status: String(data[i][5] || 'รอดำเนินการ'),
          resolveComment: String(data[i][6] || '')
        });
      }
    }
    
    // เรียงตามเวลาล่าสุดจากบนลงล่าง
    results.reverse();
    
    return { success: true, issues: results };
  } catch(e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการสืบค้น: ' + e.toString() };
  }
}

/**
 * 👮 ดึงรายการใบแจ้งปัญหาทั้งหมด สำหรับแผงควบคุม Helpdesk ของ Admin/Super Admin
 */
function getSystemIssuesForAdmin(payload) {
  try {
    var auth = _resolveAuth(payload);
    if (auth.error) return auth.error;
    
    var g = checkRole(auth.userRole, IS_ADMIN_UP, 'getSystemIssuesForAdmin');
    if (!g.allowed) return g.error;
    
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Issues');
    if (!sheet) return { success: true, issues: [] };
    
    var data = sheet.getDataRange().getValues();
    var results = [];
    
    // Headers: Timestamp (0), ReporterName (1), Agency (2), Contact (3), Detail (4), Status (5), ResolveComment (6)
    for (var i = 1; i < data.length; i++) {
      if (!data[i][0]) continue;
      var contactRaw = String(data[i][3] || '').trim();
      if (/^\d{8,9}$/.test(contactRaw)) {
        contactRaw = '0' + contactRaw;
      }
      results.push({
        timestamp: String(data[i][0]),
        reporterName: String(data[i][1] || ''),
        agency: String(data[i][2] || ''),
        contact: contactRaw,
        detail: String(data[i][4] || ''),
        status: String(data[i][5] || 'รอดำเนินการ'),
        resolveComment: String(data[i][6] || '')
      });
    }
    
    // เรียงตามล่าสุดก่อน
    results.reverse();
    
    return { success: true, issues: results };
  } catch(e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการดึงข้อมูลตั๋วปัญหา: ' + e.toString() };
  }
}

/**
 * 👮 อัปเดตสถานะและตอบกลับตั๋วปัญหา จากแผงควบคุม Helpdesk ของ Admin/Super Admin
 */
function updateSystemIssueBackend(payload) {
  try {
    var auth = _resolveAuth(payload);
    if (auth.error) return auth.error;
    
    var g = checkRole(auth.userRole, IS_ADMIN_UP, 'updateSystemIssueBackend');
    if (!g.allowed) return g.error;
    
    var timestamp = payload.timestamp ? payload.timestamp.trim() : '';
    var reporterName = payload.reporterName ? payload.reporterName.trim() : '';
    var newStatus = payload.status ? payload.status.trim() : 'รอดำเนินการ';
    var resolveComment = payload.resolveComment ? payload.resolveComment.trim() : '';
    
    if (!timestamp || !reporterName) {
      return { success: false, message: 'ข้อมูลระบุตัวตนตั๋ว (Timestamp/Reporter) ไม่ถูกต้อง' };
    }
    
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Issues');
    if (!sheet) return { success: false, message: 'ไม่พบตารางแจ้งปัญหา Issues ในระบบ' };
    
    var data = sheet.getDataRange().getValues();
    var rowIndex = -1;
    
    for (var i = 1; i < data.length; i++) {
      var ts = String(data[i][0] || '').trim();
      var rep = String(data[i][1] || '').trim();
      if (ts === timestamp && rep === reporterName) {
        rowIndex = i + 1; // 1-indexed and skip headers
        break;
      }
    }
    
    if (rowIndex === -1) {
      return { success: false, message: 'ไม่พบบันทึกตั๋วปัญหาที่ระบุในฐานข้อมูล' };
    }
    
    // อัปเดต Status และ ResolveComment
    sheet.getRange(rowIndex, 6).setValue(newStatus); // Column F
    sheet.getRange(rowIndex, 7).setValue(resolveComment); // Column G
    
    logAction(auth.userRole, 'Resolve Issue', 'จัดการตอบกลับตั๋ว: ' + reporterName + ' | สถานะใหม่: ' + newStatus);
    
    return { success: true, message: 'บันทึกคำตอบกลับและอัปเดตตั๋วปัญหาสำเร็จ' };
  } catch(e) {
    return { success: false, message: 'เกิดข้อผิดพลาดในการอัปเดตตั๋วปัญหา: ' + e.toString() };
  }
}

function seedOBECMTemplates() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('FormTemplates');
  if (!sheet) {
    sheet = ss.insertSheet('FormTemplates');
    sheet.appendRow(['FormID','FormName','AgencyID','FormJSON','Deadline','IsMultiRow']);
  }
  
  var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  var isMultiRowColIdx = headers.indexOf('IsMultiRow');
  if (isMultiRowColIdx === -1) {
    sheet.getRange(1, headers.length + 1).setValue('IsMultiRow');
    isMultiRowColIdx = headers.length;
  }
  
  var templates = [
    {
      formId: 'OBECM_F01',
      formName: 'ข้อมูลหน่วยงาน สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "director_name", "label": "ชื่อผู้บริหาร", "type": "text", "required": true },
        { "name": "position", "label": "ตำแหน่ง", "type": "text", "required": true },
        { "name": "office_address", "label": "ที่ตั้งหน่วยงาน", "type": "text", "required": true },
        { "name": "contact_number", "label": "เบอร์ติดต่อ", "type": "text", "required": true },
        { "name": "website", "label": "เว็บไซต์หน่วยงาน", "type": "text", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F02',
      formName: 'รายชื่อสถานศึกษาในสังกัด สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษา", "type": "text", "required": true },
        { "name": "tambon", "label": "ตำบลที่ตั้ง", "type": "text", "required": true },
        { "name": "amphoe", "label": "อำเภอที่ตั้ง", "type": "text", "required": true },
        { "name": "address", "label": "ที่อยู่สถานศึกษา (โดยละเอียด)", "type": "textarea", "required": true },
        { "name": "director_name", "label": "ชื่อผู้อำนวยการโรงเรียน", "type": "text", "required": true },
        { "name": "contact_info", "label": "เบอร์ติดต่อ / ID Line ผู้อำนวยการ", "type": "text", "required": true }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F03',
      formName: 'ข้อมูลนักเรียนรับทุน ม.ท.ศ. สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "student_name", "label": "ชื่อ - สกุล นักเรียนทุน", "type": "text", "required": true },
        { "name": "student_level", "label": "ระดับชั้น", "type": "text", "required": true },
        { "name": "school_name", "label": "โรงเรียนต้นสังกัด", "type": "text", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F04',
      formName: 'ข้อมูลนักเรียนรับทุนร่วมจิตต์ฯ สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "student_name", "label": "ชื่อ - สกุล นักเรียนทุน", "type": "text", "required": true },
        { "name": "student_level", "label": "ระดับชั้น", "type": "text", "required": true },
        { "name": "school_name", "label": "โรงเรียนต้นสังกัด", "type": "text", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F05',
      formName: 'บุคลากรทำหน้าที่สอนและวุฒิการศึกษา สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษาที่รายงาน", "type": "text", "required": true },
        { "type": "section", "label": "ข้อมูลผู้อำนวยการโรงเรียน" },
        { "name": "dir_male", "label": "ผู้อำนวยการ (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "dir_female", "label": "ผู้อำนวยการ (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "ข้อมูลข้าราชการครู" },
        { "name": "tchr_male", "label": "ข้าราชการครู (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "tchr_female", "label": "ข้าราชการครู (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "ข้อมูลข้าราชการพลเรือน" },
        { "name": "civil_male", "label": "ข้าราชการพลเรือน (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "civil_female", "label": "ข้าราชการพลเรือน (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "ข้อมูลพนักงานราชการ" },
        { "name": "emp_male", "label": "พนักงานราชการ (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "emp_female", "label": "พนักงานราชการ (หญิง)", "type": "number", "required": true, "min": 0 }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F06',
      formName: 'จำแนกตามรายวิชาเอกที่สอน สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษาที่รายงาน", "type": "text", "required": true },
        { "type": "section", "label": "วิชาเอกปฐมวัย" },
        { "name": "maj_early_male", "label": "เอกปฐมวัย (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "maj_early_female", "label": "เอกปฐมวัย (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "วิชาเอกสังคมศึกษา" },
        { "name": "maj_social_male", "label": "เอกสังคม (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "maj_social_female", "label": "เอกสังคม (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "วิชาเอกวิทยาศาสตร์" },
        { "name": "maj_science_male", "label": "เอกวิทยาศาสตร์ (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "maj_science_female", "label": "เอกวิทยาศาสตร์ (หญิง)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "วิชาเอกภาษาอังกฤษ" },
        { "name": "maj_english_male", "label": "เอกภาษาอังกฤษ (ชาย)", "type": "number", "required": true, "min": 0 },
        { "name": "maj_english_female", "label": "เอกภาษาอังกฤษ (หญิง)", "type": "number", "required": true, "min": 0 }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F07',
      formName: 'นักเรียนออกกลางคันจำแนกตามสาเหตุสำคัญ สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษาที่รายงาน", "type": "text", "required": true },
        { "type": "section", "label": "1. สาเหตุ: ฐานะยากจน" },
        { "name": "poor_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "poor_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "poor_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "2. สาเหตุ: มีปัญหาครอบครัว" },
        { "name": "family_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "family_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "family_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "3. สาเหตุ: สมรส" },
        { "name": "married_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "married_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "married_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "4. สาเหตุ: มีปัญหาการปรับตัว" },
        { "name": "adjust_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "adjust_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "adjust_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "5. สาเหตุ: ต้องคดี/ถูกจับ" },
        { "name": "arrest_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "arrest_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "arrest_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "6. สาเหตุ: เจ็บป่วย/อุบัติเหตุ" },
        { "name": "sick_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "sick_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "sick_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "7. สาเหตุ: อพยพตามครอบครัว" },
        { "name": "migrate_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "migrate_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "migrate_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "8. สาเหตุ: หาเลี้ยงครอบครัว" },
        { "name": "work_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "work_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "work_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 },
        { "type": "section", "label": "9. สาเหตุ: กรณีอื่น ๆ" },
        { "name": "other_pri", "label": "ระดับประถม (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "other_mid", "label": "ระดับ ม.ต้น (คน)", "type": "number", "required": true, "min": 0 },
        { "name": "other_high", "label": "ระดับ ม.ปลาย (คน)", "type": "number", "required": true, "min": 0 }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F08',
      formName: 'โครงการอนุรักษ์พันธุกรรมพืชฯ สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษา", "type": "text", "required": true },
        { "name": "location", "label": "ที่ตั้งสถานศึกษา", "type": "text", "required": true },
        { "name": "accept_date", "label": "วันที่ตอบรับสมาชิก", "type": "date", "required": true },
        { "name": "member_no", "label": "เลขที่สมาชิก", "type": "text", "required": true },
        { "name": "has_badge", "label": "สถานะการรับป้ายโครงการ", "type": "select", "opts": "ได้รับแล้ว | ยังไม่ได้รับ", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F09',
      formName: 'โครงการพัฒนาเด็กและเยาวชนในถิ่นทุรกันดาร (กพด.) สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษา", "type": "text", "required": true },
        { "name": "address", "label": "ที่อยู่สถานศึกษา", "type": "textarea", "required": true },
        { "name": "contact_phone", "label": "เบอร์ติดต่อ", "type": "text", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F10',
      formName: 'โครงการสถานศึกษาพอเพียง สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษา", "type": "text", "required": true },
        { "name": "address", "label": "ที่อยู่สถานศึกษา", "type": "textarea", "required": true },
        { "name": "operation_status", "label": "ผลการดำเนินงาน", "type": "select", "opts": "ผ่านการประเมินแล้ว | อยู่ระหว่างดำเนินการ | ยังไม่ได้ดำเนินการ", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    },
    {
      formId: 'OBECM_F11',
      formName: 'โครงการสถานศึกษาสีขาว ปลอดยาเสพติดและอบายมุข สพม.สกลนคร',
      agencyId: 'OBEC_M',
      config: [
        { "name": "report_title", "label": "หัวข้อการรายงาน", "type": "text", "required": true },
        { "name": "school_name", "label": "ชื่อสถานศึกษา", "type": "text", "required": true },
        { "name": "award_level", "label": "ระดับผลงานดีเด่นที่ได้รับ", "type": "select", "opts": "ระดับทอง | ระดับเพชร | รักษามาตรฐานเพชร ปีที่ 1 | รักษามาตรฐานเพชร ปีที่ 2", "required": true },
        { "name": "notes", "label": "หมายเหตุ", "type": "textarea", "required": false }
      ],
      deadline: ''
    }
  ];
  
  var data = sheet.getDataRange().getValues();
  for (var t = 0; t < templates.length; t++) {
    var item = templates[t];
    var existRow = -1;
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === item.formId) {
        existRow = i + 1;
        break;
      }
    }
    
    var rowData = [
      item.formId,
      item.formName,
      item.agencyId,
      JSON.stringify(item.config),
      item.deadline
    ];
    
    var isMultiVal = (item.formId !== 'OBECM_F01' && item.formId !== 'OBECM_F07') ? 1 : 0;
    
    if (existRow > -1) {
      sheet.getRange(existRow, 1, 1, rowData.length).setValues([rowData]);
      sheet.getRange(existRow, isMultiRowColIdx + 1).setValue(isMultiVal);
    } else {
      sheet.appendRow(rowData);
      var newLastRow = sheet.getLastRow();
      sheet.getRange(newLastRow, isMultiRowColIdx + 1).setValue(isMultiVal);
    }
  }
  
  _invalidateFormsCache();
  return { success: true, message: 'ลงทะเบียนฟอร์มสำเร็จ: ' + templates.map(function(x){ return x.formId; }).join(', ') };
}



