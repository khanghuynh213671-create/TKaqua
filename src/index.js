async function createSignature(dataStr, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(dataStr));
  return Array.from(new Uint8Array(signature))
    .map(function (b) { return b.toString(16).padStart(2, "0"); })
    .join("");
}

/* ================= Cấu hình ================= */
const FIREBASE_PROJECT_ID = "tk-aqua";
const FS_BASE = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents";
const SITE_URL = "https://tkaqua.khanghuynh213671.workers.dev";
const DEFAULT_SHEET_WEBHOOK = "https://script.google.com/macros/s/AKfycbwIvuLes3qi8AH3AINWDDzLPVigzNvp5kDLhYl0azjWWfqf3C2j9ynNSD4Wr7lzfpVvIg/exec";

const CATALOG_FISH_CSV = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQp8_YWn7P7HMP4k2JbLNI2gkrwATBP9zkJumK96bi2dwU8k2OM1AbAgAICyUayeZj4kqkro_nciT8N/pub?output=csv";
const CATALOG_ACC_CSV = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQp8_YWn7P7HMP4k2JbLNI2gkrwATBP9zkJumK96bi2dwU8k2OM1AbAgAICyUayeZj4kqkro_nciT8N/pub?gid=1785201873&single=true&output=csv";

const SHIPPING = {
  "J&T Miền Nam (1-2 ngày, đã gồm thùng)": 40000,
  "J&T Miền Trung/Bắc (2-3 ngày, đã gồm thùng)": 50000,
  "Chành xe (Ship + Chành + Thùng)": 100000
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store, no-cache, must-revalidate"
};

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...corsHeaders }
  });
}

function base64ToBlob(base64Str, defaultMime) {
  try {
    if (!base64Str || typeof base64Str !== "string") return null;
    const parts = base64Str.split(",");
    let mime = defaultMime || "image/jpeg";
    if (parts.length > 1 && parts[0].indexOf("data:") === 0) {
      const match = parts[0].match(/data:(.*?);base64/);
      if (match) mime = match[1];
    }
    const raw = parts.length > 1 ? parts[1] : parts[0];
    const bin = atob(raw.replace(/\s/g, ""));
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      arr[i] = bin.charCodeAt(i);
    }
    return new Blob([arr], { type: mime });
  } catch (err) {
    console.error("Lỗi base64ToBlob:", err);
    return null;
  }
}

/* ================= Giới hạn tần suất ================= */
const _rl = new Map();
function rateLimited(request, key, limit, windowMs) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const k = key + ":" + ip, now = Date.now();
  let e = _rl.get(k);
  if (!e || now > e.reset) { e = { n: 0, reset: now + windowMs }; _rl.set(k, e); }
  e.n++;
  if (_rl.size > 5000) _rl.clear();
  return e.n > limit;
}

/* ================= Chữ ký webhook payOS ================= */
function sortObjByKey(obj) {
  const out = {};
  Object.keys(obj).sort().forEach(function (k) { out[k] = obj[k]; });
  return out;
}

function webhookDataToString(data) {
  return Object.keys(data).sort().map(function (k) {
    let v = data[k];
    if (v === null || v === undefined || v === "null" || v === "undefined") {
      v = "";
    } else if (Array.isArray(v)) {
      v = JSON.stringify(v.map(function (i) {
        return (i && typeof i === "object") ? sortObjByKey(i) : i;
      }));
    } else if (typeof v === "object") {
      v = JSON.stringify(sortObjByKey(v));
    }
    return k + "=" + v;
  }).join("&");
}

async function verifyPayosWebhook(webhookData, checksumKey) {
  if (!webhookData || !webhookData.data || !webhookData.signature || !checksumKey) return false;
  const expected = await createSignature(webhookDataToString(webhookData.data), checksumKey);
  const given = String(webhookData.signature).toLowerCase();
  if (expected.length !== given.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ given.charCodeAt(i);
  }
  return diff === 0;
}

/* ================= Firestore Service Account ================= */
function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlStr(str) { return b64url(new TextEncoder().encode(str)); }

let _token = { value: "", exp: 0 };
async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (_token.value && _token.exp - 60 > now) return _token.value;
  if (!env.FIREBASE_SERVICE_ACCOUNT) throw new Error("Thiếu secret FIREBASE_SERVICE_ACCOUNT");

  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const header = b64urlStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64urlStr(JSON.stringify({
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));
  const pem = String(sa.private_key).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), function (c) { return c.charCodeAt(0); });
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(header + "." + claim));
  const jwt = header + "." + claim + "." + b64url(new Uint8Array(sig));

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + jwt
  });
  const j = await res.json();
  if (!j.access_token) throw new Error("Không lấy được token Firebase");
  _token = { value: j.access_token, exp: now + (j.expires_in || 3600) };
  return _token.value;
}

async function fsFetch(env, url, options) {
  const token = await getAccessToken(env);
  const opts = Object.assign({}, options || {});
  opts.headers = Object.assign({ "Content-Type": "application/json", "Authorization": "Bearer " + token }, opts.headers || {});
  return fetch(url, opts);
}

function fsValue(v) {
  if (!v) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fsValue);
  if ("mapValue" in v) return fsFields(v.mapValue.fields || {});
  return null;
}
function fsFields(fields) {
  const out = {};
  Object.keys(fields).forEach(function (k) { out[k] = fsValue(fields[k]); });
  return out;
}
function toFs(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFs) } };
  return { mapValue: { fields: toFsFields(v) } };
}
function toFsFields(obj) {
  const out = {};
  Object.keys(obj).forEach(function (k) { out[k] = toFs(obj[k]); });
  return out;
}

async function queryOrders(env, field, value, limit) {
  const res = await fsFetch(env, FS_BASE + ":runQuery", {
    method: "POST",
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: "don_hang" }],
        where: { fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: { stringValue: value } } },
        limit: limit || 1
      }
    })
  });
  const data = await res.json();
  const errObj = Array.isArray(data) ? (data[0] && data[0].error) : data && data.error;
  if (errObj) throw new Error("Firestore: " + (errObj.status || errObj.code || "") + " - " + String(errObj.message || "").slice(0, 500));
  if (!Array.isArray(data)) throw new Error("Firestore trả về dữ liệu không hợp lệ");
  return data.filter(function (x) { return x.document; }).map(function (x) { return x.document; });
}

async function findOrderDoc(env, orderCode) {
  const docs = await queryOrders(env, "ma_don", "TKA-" + orderCode, 1);
  return docs[0] || null;
}

/* ================= Bảng giá chuẩn ================= */
function parseCsvRows(str) {
  const rows = []; let row = [], cur = "", q = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (q) {
      if (c === '"') { if (str[i + 1] === '"') { cur += '"'; i++; } else { q = false; } }
      else { cur += c; }
    } else if (c === '"') { q = true; }
    else if (c === ",") { row.push(cur); cur = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && str[i + 1] === "\n") i++;
      row.push(cur); cur = ""; rows.push(row); row = [];
    } else { cur += c; }
  }
  if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
  return rows;
}

async function loadCatalog(csvUrl) {
  const res = await fetch(csvUrl, { cf: { cacheTtl: 30, cacheEverything: true } });
  const rows = parseCsvRows(await res.text());
  const out = [];
  if (rows.length < 2) return out;
  const head = rows[0].map(function (h) { return h.replace(/\s/g, ""); });
  const iName = head.findIndex(function (h) { return h === "TenCa" || h === "TenSP"; });
  const iPrice = head.indexOf("Gia");
  const iSize = head.indexOf("Size");
  const iStock = head.indexOf("SoLuong");
  if (iName < 0 || iPrice < 0) return out;
  for (let r = 1; r < rows.length; r++) {
    const name = String(rows[r][iName] || "").trim();
    const price = parseInt(rows[r][iPrice], 10);
    if (!name || !(price > 0)) continue;
    out.push({
      name: name,
      price: price,
      size: iSize >= 0 ? String(rows[r][iSize] || "").trim() : "",
      stock: iStock >= 0 ? (parseInt(rows[r][iStock], 10) || 0) : 0
    });
  }
  return out;
}

function findCatalogItem(list, name, size) {
  let c = list.filter(function (x) { return x.name === name; });
  if (c.length > 1) {
    const bySize = c.filter(function (x) { return x.size === size; });
    if (bySize.length) c = bySize;
  }
  return c.length === 1 ? c[0] : (c.length > 1 ? c[0] : null);
}

function cleanText(s, max) {
  return String(s == null ? "" : s).replace(/[\u0300-\u036f]/g, "").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
function normalizePhone(p) {
  let s = String(p || "").replace(/[\s.\-+()]/g, "");
  if (/^84\d{9}$/.test(s)) s = "0" + s.slice(2);
  return s;
}
const isPhone = function (p) { return /^0\d{9}$/.test(p); };

function maskPhone(p) { p = String(p || ""); return p.length >= 7 ? p.slice(0, 3) + "****" + p.slice(-3) : "***"; }
function maskName(n) {
  return String(n || "").split(" ").filter(Boolean).map(function (w) { return w.charAt(0) + "***"; }).join(" ");
}
function maskAddress(a) { a = String(a || ""); return a.length <= 3 ? "***" : a.slice(0, 3) + "***"; }

function publicOrder(o) {
  return {
    ma_don: o.ma_don,
    order_code_num: o.order_code_num,
    trang_thai: o.trang_thai,
    paid: o.paid === true,
    ten_khach: maskName(o.ten_khach),
    so_dien_thoai: maskPhone(o.so_dien_thoai),
    dia_chi: maskAddress(o.dia_chi),
    phuong_thuc_ship: o.phuong_thuc_ship,
    phi_ship: o.phi_ship,
    tien_hang: o.tien_hang,
    tong_tien: o.tong_tien,
    tong_so_luong: o.tong_so_luong,
    san_pham: Array.isArray(o.san_pham) ? o.san_pham.map(function (sp) {
      return { loai: sp.loai, ten_ca: sp.ten_ca, size: sp.size, so_luong: sp.so_luong, don_gia: sp.don_gia, thanh_tien: sp.thanh_tien };
    }) : [],
    payos: o.paid === true ? null : (o.payos || null)
  };
}

/* ================= payOS ================= */
async function createPayosLink(env, orderCode, amount, customDesc) {
  const description = String(customDesc || ("Than tang TK TKA-" + orderCode)).slice(0, 25);
  const signData = "amount=" + amount + "&cancelUrl=" + SITE_URL + "&description=" + description + "&orderCode=" + orderCode + "&returnUrl=" + SITE_URL;
  const signature = await createSignature(signData, env.PAYOS_CHECKSUM_KEY);
  const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-client-id": env.PAYOS_CLIENT_ID,
      "x-api-key": env.PAYOS_API_KEY
    },
    body: JSON.stringify({
      orderCode: orderCode,
      amount: amount,
      description: description,
      cancelUrl: SITE_URL,
      returnUrl: SITE_URL,
      signature: signature
    })
  });
  return response.json();
}

/* ================= Discord Thông Báo ================= */
async function notifyDiscordPaid(discordUrl, order, orderCode) {
  if (!discordUrl) return;

  const items = Array.isArray(order.san_pham) ? order.san_pham : [];
  let detail = "";
  items.forEach(function (sp, i) {
    const stt = String(i + 1).padStart(2, "0");
    const dv = sp.loai === "Phụ kiện" ? "sp" : "con";
    const sz = sp.size ? " (" + sp.size + ")" : "";
    detail += stt + ". " + sp.ten_ca + sz + "\n    SL: " + sp.so_luong + " " + dv + "  ×  " +
      Number(sp.don_gia || 0).toLocaleString("vi-VN") + "đ  =  " +
      Number(sp.thanh_tien || 0).toLocaleString("vi-VN") + "đ\n";
  });
  if (detail.length > 950) detail = detail.slice(0, 950) + "...\n";

  const phiShip = Number(order.phi_ship || 0);
  const tongTien = Number(order.tong_tien || 0);

  await fetch(discordUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content: "✅ **ĐƠN HÀNG #TKA-" + orderCode + " ĐÃ THANH TOÁN THÀNH CÔNG**",
      allowed_mentions: { parse: [] },
      embeds: [{
        title: "HÓA ĐƠN #TKA-" + orderCode,
        color: 5763719,
        fields: [
          { name: "Khách hàng", value: "**" + (order.ten_khach || "") + "**", inline: true },
          { name: "Điện thoại", value: "**" + (order.so_dien_thoai || "") + "**", inline: true },
          { name: "Thời gian thanh toán", value: new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" }), inline: true },
          { name: "Địa chỉ", value: order.dia_chi || "—", inline: false },
          { name: "Vận chuyển", value: (order.phuong_thuc_ship || "Tiêu chuẩn") + " (+" + phiShip.toLocaleString("vi-VN") + "đ)", inline: false },
          { name: "Danh mục (" + (order.tong_so_luong || items.length) + " món)", value: "```yaml\n" + detail + "```", inline: false },
          { name: "Ghi chú", value: order.ghi_chu || "Không", inline: true },
          { name: "ĐÃ THANH TOÁN", value: "**" + tongTien.toLocaleString("vi-VN") + " VNĐ**", inline: true }
        ],
        footer: { text: "TK aqua · Hệ thống Tự Động" }
      }]
    })
  });
}

/* ================= Google Sheet ================= */
async function callSheet(env, payload) {
  const sheetUrl = env.GOOGLE_SHEET_WEBHOOK_URL || DEFAULT_SHEET_WEBHOOK;
  return fetch(sheetUrl, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify(Object.assign({}, payload, { secret: env.SHEET_SECRET || "" })),
    redirect: "follow"
  });
}

function vnNow() {
  const p = {};
  new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Ho_Chi_Minh", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
    .formatToParts(new Date()).forEach(function (x) { p[x.type] = x.value; });
  return p.day + "/" + p.month + "/" + p.year + " " + (p.hour === "24" ? "00" : p.hour) + ":" + p.minute + ":" + p.second;
}

function updateSheetPaid(env, maDon, order) {
  const items = Array.isArray(order && order.san_pham) ? order.san_pham : [];
  return callSheet(env, {
    action: "paid", ma_don: maDon, tinh_trang: "Đã thanh toán",
    tong_tien: Number(order && order.tong_tien) || 0,
    items: items.map(function (sp) {
      return { type: sp.loai === "Phụ kiện" ? "acc" : "fish", name: sp.ten_ca, size: sp.size || "", qty: sp.so_luong };
    })
  });
}

function createSheetRow(env, order, maDon) {
  const items = Array.isArray(order.san_pham) ? order.san_pham : [];
  const chiTiet = items.map(function (sp) {
    const dv = sp.loai === "Phụ kiện" ? "sp" : "con";
    const sz = sp.size ? " (" + sp.size + ")" : "";
    return sp.ten_ca + sz + " x" + sp.so_luong + " " + dv;
  }).join(", ") + " | Ship: " + (order.phuong_thuc_ship || "Tiêu chuẩn") + " (+" + Number(order.phi_ship || 0).toLocaleString("vi-VN") + "đ)";
  const note = order.ghi_chu && order.ghi_chu !== "Không có" ? order.ghi_chu + " | " : "";
  return callSheet(env, {
    action: "create",
    tinh_trang: "Chưa thanh toán",
    ma_don: maDon,
    thoi_gian: vnNow(),
    ten_khach: sheetSafe(order.ten_khach),
    so_dien_thoai: order.so_dien_thoai,
    dia_chi: sheetSafe(order.dia_chi),
    chi_tiet_sp: sheetSafe(chiTiet),
    chi_tiet_ca: sheetSafe(chiTiet),
    tong_so_luong: order.tong_so_luong,
    tong_tien: order.tong_tien,
    ghi_chu: sheetSafe(note + (order.phuong_thuc_ship || "Tiêu chuẩn"))
  });
}

async function markOrderPaid(orderCode, env, paidAmount) {
  try {
    const document = await findOrderDoc(env, orderCode);
    if (!document) return false;

    const fields = document.fields || {};
    const alreadyPaid =
      (fields.paid && fields.paid.booleanValue === true) ||
      (fields.trang_thai && fields.trang_thai.stringValue === "Đã thanh toán");
    if (alreadyPaid) return false;

    const expected = fsValue(fields.tong_tien);
    if (!(Number(expected) > 0) || !(Number(paidAmount) >= Number(expected))) {
      return false;
    }

    const patchUrl = "https://firestore.googleapis.com/v1/" + document.name +
      "?updateMask.fieldPaths=trang_thai&updateMask.fieldPaths=paid&updateMask.fieldPaths=ngay_thanh_toan" +
      "&currentDocument.updateTime=" + encodeURIComponent(document.updateTime);
    const patchRes = await fsFetch(env, patchUrl, {
      method: "PATCH",
      body: JSON.stringify({
        fields: {
          trang_thai: { stringValue: "Đã thanh toán" },
          paid: { booleanValue: true },
          ngay_thanh_toan: { timestampValue: new Date().toISOString() }
        }
      })
    });
    if (!patchRes.ok) return false;

    const order = fsFields(fields);
    await Promise.all([
      notifyDiscordPaid(env.DISCORD_WEBHOOK_URL, order, orderCode).catch(function (e) { console.error(e); }),
      updateSheetPaid(env, "TKA-" + orderCode, order).catch(function (e) { console.error(e); })
    ]);
    return true;
  } catch (e) {
    console.error("markOrderPaid error:", e);
  }
  return false;
}

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
async function readJson(request, maxBytes) {
  const txt = await request.text();
  if (txt.length > (maxBytes || 35000000)) throw new HttpError(413, "Dữ liệu quá lớn");
  try { return JSON.parse(txt); } catch (e) { throw new HttpError(400, "Dữ liệu không hợp lệ"); }
}
function errResponse(err, fallback) {
  if (err instanceof HttpError) return jsonResponse({ error: err.message }, err.status);
  return jsonResponse({ error: fallback }, 500);
}
function sheetSafe(v) {
  const t = String(v == null ? "" : v);
  return /^[=+\-@\t\r]/.test(t) ? "'" + t : t;
}

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' blob: data: https:; frame-src https://www.google.com https://maps.google.com https://drive.google.com https://www.youtube.com https://pay.payos.vn https://www.facebook.com; connect-src 'self' https://docs.google.com https://*.googleusercontent.com https://api-merchant.payos.vn https://*.googleapis.com https://*.firebaseio.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Permissions-Policy": "camera=(self), microphone=(self), geolocation=()"
};
function withSecurity(res) {
  const h = new Headers(res.headers);
  for (const k in SECURITY_HEADERS) h.set(k, SECURITY_HEADERS[k]);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

/* ================= Phiên đăng nhập POS (token ký HMAC) ================= */
function tokenSecret(env) { return env.POS_TOKEN_SECRET || env.SHEET_SECRET || ""; }
function b64urlDecodeStr(t) {
  const b = atob(String(t).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(t).length + 3) % 4));
  return new TextDecoder().decode(Uint8Array.from(b, function (c) { return c.charCodeAt(0); }));
}
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function signToken(env, user) {
  const body = b64urlStr(JSON.stringify({ p: user.phone, n: user.name, r: user.role, e: Date.now() + 14 * 86400000 }));
  return body + "." + await createSignature(body, tokenSecret(env));
}
async function verifyToken(request, env) {
  try {
    const key = tokenSecret(env);
    const h = request.headers.get("Authorization") || "";
    const t = h.startsWith("Bearer ") ? h.slice(7) : "";
    const parts = t.split(".");
    if (!key || parts.length !== 2) return null;
    if (!safeEqual(await createSignature(parts[0], key), parts[1])) return null;
    const u = JSON.parse(b64urlDecodeStr(parts[0]));
    if (!u || !(u.e > Date.now()) || !isPhone(u.p)) return null;
    return { phone: u.p, name: u.n, role: u.r };
  } catch (e) { return null; }
}
const _rlk = new Map();
function rateLimitedKey(key, limit, windowMs) {
  const now = Date.now();
  let e = _rlk.get(key);
  if (!e || now > e.reset) { e = { n: 0, reset: now + windowMs }; _rlk.set(key, e); }
  e.n++;
  if (_rlk.size > 5000) _rlk.clear();
  return e.n > limit;
}
async function pbkdf2Hex(pass, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/../g), function (h) { return parseInt(h, 16); });
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 100000 }, k, 256);
  return Array.from(new Uint8Array(bits)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
async function hashPassword(pass) {
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  return "pbkdf2$" + salt + "$" + await pbkdf2Hex(pass, salt);
}
async function checkPassword(stored, pass) {
  stored = String(stored || "");
  if (stored.startsWith("pbkdf2$")) {
    const p = stored.split("$");
    return { ok: p.length === 3 && safeEqual(await pbkdf2Hex(pass, p[1]), p[2]), upgrade: false };
  }
  return { ok: stored !== "" && safeEqual(stored, pass), upgrade: true }; // mật khẩu cũ lưu thô -> tự nâng cấp
}

/* ================= ĐIỀU PHỐI API ROUTING ================= */
const handler = {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 1. TẠO ĐƠN WEB ONLINE
    if (url.pathname === "/api/create-order" && request.method === "POST") {
      try {
        if (rateLimited(request, "order", 8, 10 * 60 * 1000)) {
          return jsonResponse({ error: "Bạn thao tác quá nhanh, vui lòng thử lại sau ít phút." }, 429);
        }
        const body = await readJson(request, 20000);
        const c = body && body.customer ? body.customer : {};
        const name = cleanText(c.name, 80);
        const phone = normalizePhone(c.phone);
        const address = cleanText(c.address, 300);
        const note = cleanText(c.note, 300);
        const shipLabel = String(c.shipMethod || "");

        if (name.length < 2) return jsonResponse({ error: "Họ tên không hợp lệ" }, 400);
        if (!isPhone(phone)) return jsonResponse({ error: "Số điện thoại không hợp lệ" }, 400);
        if (address.length < 5) return jsonResponse({ error: "Địa chỉ không hợp lệ" }, 400);
        if (!Object.prototype.hasOwnProperty.call(SHIPPING, shipLabel)) return jsonResponse({ error: "Phương thức vận chuyển không hợp lệ" }, 400);

        const items = Array.isArray(body.items) ? body.items : [];
        if (!items.length || items.length > 40) return jsonResponse({ error: "Giỏ hàng không hợp lệ" }, 400);

        const catalogs = await Promise.all([loadCatalog(CATALOG_FISH_CSV), loadCatalog(CATALOG_ACC_CSV)]);
        const lines = [];
        const used = {};
        let tienHang = 0, tongSoLuong = 0;
        for (const it of items) {
          if (!it || typeof it !== "object") return jsonResponse({ error: "Giỏ hàng không hợp lệ" }, 400);
          const qty = Number(it.qty);
          if (!Number.isInteger(qty) || qty < 1 || qty > 999) return jsonResponse({ error: "Số lượng không hợp lệ" }, 400);
          const isAcc = it.type === "acc";
          const prod = findCatalogItem(isAcc ? catalogs[1] : catalogs[0], String(it.name || "").trim(), String(it.size || "").trim());
          if (!prod) return jsonResponse({ error: "Sản phẩm không còn trong danh mục: " + cleanText(it.name, 60) }, 400);
          const ukey = (isAcc ? "a|" : "f|") + prod.name + "|" + prod.size;
          used[ukey] = (used[ukey] || 0) + qty;
          if (used[ukey] > prod.stock) return jsonResponse({ error: "Sản phẩm \"" + prod.name + "\" không đủ hàng" }, 400);
          const thanhTien = prod.price * qty;
          tienHang += thanhTien;
          tongSoLuong += qty;
          lines.push({ loai: isAcc ? "Phụ kiện" : "Cá cảnh", ten_ca: prod.name, size: prod.size, so_luong: qty, don_gia: prod.price, thanh_tien: thanhTien });
        }

        const phiShip = SHIPPING[shipLabel];
        const tongTien = tienHang + phiShip;

        const prev = await queryOrders(env, "so_dien_thoai", phone, 200);
        const hourAgo = Date.now() - 3600 * 1000;
        const pending = prev.filter(function (d) {
          const f = fsFields(d.fields || {});
          return !f.paid && (Date.parse(f.ngay_dat || "") || 0) > hourAgo;
        }).length;
        if (pending >= 5) return jsonResponse({ error: "Bạn có quá nhiều đơn chưa thanh toán, vui lòng thanh toán hoặc thử lại sau." }, 429);

        let maSo = 0;
        for (let i = 0; i < 5; i++) {
          const rnd = crypto.getRandomValues(new Uint32Array(1))[0] % 90 + 10;
          const candidate = Number(String(Date.now()).slice(-6) + String(rnd));
          if (!(await findOrderDoc(env, candidate))) { maSo = candidate; break; }
        }
        if (!maSo) return jsonResponse({ error: "Không tạo được mã đơn, vui lòng thử lại" }, 500);

        const order = {
          ma_don: "TKA-" + maSo,
          order_code_num: maSo,
          trang_thai: "Chờ thanh toán",
          paid: false,
          ten_khach: name,
          so_dien_thoai: phone,
          dia_chi: address,
          phuong_thuc_ship: shipLabel,
          phi_ship: phiShip,
          tien_hang: tienHang,
          ghi_chu: note || "Không có",
          san_pham: lines,
          tong_so_luong: tongSoLuong,
          tong_tien: tongTien,
          ngay_dat: new Date()
        };

        const createRes = await fsFetch(env, FS_BASE + "/don_hang?documentId=" + encodeURIComponent("TKA-" + maSo), {
          method: "POST",
          body: JSON.stringify({ fields: toFsFields(order) })
        });
        if (!createRes.ok) return jsonResponse({ error: "Không lưu được đơn hàng" }, 500);

        let payos = null;
        try {
          const resData = await createPayosLink(env, maSo, tongTien);
          if (resData && resData.data && (resData.data.qrCode || resData.data.checkoutUrl)) {
            payos = {
              qrCode: resData.data.qrCode || "",
              checkoutUrl: resData.data.checkoutUrl || "",
              accountNumber: resData.data.accountNumber || "",
              description: resData.data.description || ""
            };
            await fsFetch(env, FS_BASE + "/don_hang/" + encodeURIComponent("TKA-" + maSo) + "?updateMask.fieldPaths=payos", {
              method: "PATCH",
              body: JSON.stringify({ fields: { payos: toFs(payos) } })
            });
          }
        } catch (e) {
          console.error("payOS error:", e);
        }

        await createSheetRow(env, order, "TKA-" + maSo).catch(function (e) { console.error("Sheet error:", e); });

        const pub = publicOrder(Object.assign({}, order, { payos: payos }));
        pub.ten_khach = name; pub.so_dien_thoai = phone; pub.dia_chi = address;
        return jsonResponse({ ok: true, order: pub, payos: payos });
      } catch (err) {
        return errResponse(err, "Không thể tạo đơn lúc này");
      }
    }

    // 2. TRA CỨU ĐƠN TRÊN WEB
    if (url.pathname === "/api/lookup" && request.method === "POST") {
      try {
        if (rateLimited(request, "lookup", 20, 60 * 1000)) {
          return jsonResponse({ error: "Bạn tra cứu quá nhanh, vui lòng thử lại sau ít phút." }, 429);
        }
        const body = await readJson(request, 2000);
        const kw = cleanText(body && body.q, 40);
        if (!kw) return jsonResponse({ orders: [] });

        let docs = [];
        const phone = normalizePhone(kw);
        if (isPhone(phone)) {
          docs = await queryOrders(env, "so_dien_thoai", phone, 500);
          docs.sort(function (a, b) {
            const ta = Date.parse(fsValue((a.fields || {}).ngay_dat) || "") || 0;
            const tb = Date.parse(fsValue((b.fields || {}).ngay_dat) || "") || 0;
            return tb - ta;
          });
          docs = docs.slice(0, 20);
        } else {
          let code = kw.toUpperCase().replace(/^#/, "").replace(/\s+/g, "");
          if (!code.startsWith("TKA-")) code = "TKA-" + code.replace(/^TKA/, "");
          if (!/^TKA-\d{6,12}$/.test(code)) return jsonResponse({ orders: [] });
          docs = await queryOrders(env, "ma_don", code, 1);
        }
        const orders = docs.map(function (d) { return publicOrder(fsFields(d.fields || {})); });
        return jsonResponse({ orders: orders });
      } catch (err) {
        return errResponse(err, "Không tra cứu được lúc này");
      }
    }

    // 3. TẠO MÃ THANH TOÁN CHO POS (cần đăng nhập)
    if (url.pathname === "/api/create-payment" && request.method === "POST") {
      try {
        if (!(await verifyToken(request, env))) return jsonResponse({ error: "Chưa đăng nhập" }, 401);
        const body = await readJson(request, 10000);
        const orderCode = Number(body.orderCode);
        const amount = Number(body.amount);
        if (!Number.isSafeInteger(orderCode) || orderCode < 1000) return jsonResponse({ error: "Mã đơn không hợp lệ" }, 400);
        if (!Number.isInteger(amount) || amount < 1000 || amount > 200000000) return jsonResponse({ error: "Số tiền không hợp lệ" }, 400);
        const description = cleanText(body.description || ("POS TKA-" + orderCode), 25);
        const resData = await createPayosLink(env, orderCode, amount, description);
        return jsonResponse(resData);
      } catch (err) {
        return errResponse(err, "Không tạo được mã thanh toán");
      }
    }

    // 4. KIỂM TRA TRẠNG THÁI THANH TOÁN
    if (url.pathname === "/api/check-payment" && request.method === "GET") {
      try {
        if (rateLimited(request, "check", 120, 60 * 1000)) return jsonResponse({ error: "Too many requests" }, 429);
        const orderCode = url.searchParams.get("orderCode");
        if (!/^\d{1,12}$/.test(String(orderCode || ""))) return jsonResponse({ error: "Mã đơn không hợp lệ" }, 400);

        const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests/" + orderCode, {
          method: "GET",
          headers: {
            "x-client-id": env.PAYOS_CLIENT_ID,
            "x-api-key": env.PAYOS_API_KEY
          }
        });
        const resData = await response.json();

        if (resData && resData.data) {
          const d = resData.data;
          if (d.status === "PAID" || (d.amountPaid > 0 && d.amountPaid >= d.amount)) {
            const paid = d.amountPaid > 0 ? d.amountPaid : d.amount;
            await markOrderPaid(orderCode, env, paid);
          }
          return jsonResponse({ code: resData.code, data: { id: d.id, status: d.status, amount: d.amount, amountPaid: d.amountPaid } });
        }
        return jsonResponse({ code: resData.code, data: null });
      } catch (err) {
        return jsonResponse({ error: "Không kiểm tra được thanh toán" }, 500);
      }
    }

    // 5. WEBHOOK PAYOS TỰ ĐỘNG
    if (url.pathname === "/api/payos-webhook" && request.method === "POST") {
      try {
        const webhookData = await readJson(request, 20000);
        const validSignature = await verifyPayosWebhook(webhookData, env.PAYOS_CHECKSUM_KEY);
        if (!validSignature) return jsonResponse({ error: "Invalid signature" }, 401);

        if (webhookData.code === "00" && webhookData.data) {
          const orderCode = webhookData.data.orderCode;
          if (Number.isSafeInteger(orderCode) && orderCode > 1000) {
            await markOrderPaid(orderCode, env, webhookData.data.amount);
          }
        }
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Bad request" }, 400);
      }
    }

    // 6. GỬI DISCORD: CHIA CHÙM (BATCHING) CHO PHÉP NHIỀU ẢNH/VIDEO KHÔNG GIỚI HẠN
    if (url.pathname === "/api/notify" && request.method === "POST") {
      try {
        if (!(await verifyToken(request, env))) return jsonResponse({ error: "Chưa đăng nhập" }, 401);
        if (rateLimited(request, "notify", 60, 60 * 1000)) return jsonResponse({ error: "Thao tác quá nhanh" }, 429);
        const payload = await readJson(request, 35000000);
        let targetWebhook = env.DISCORD_WEBHOOK_URL;

        if (payload.is_checkin) {
          targetWebhook = env.CHECKIN_DISCORD_WEBHOOK_URL || env.POS_DISCORD_WEBHOOK_URL || env.DISCORD_WEBHOOK_URL;
        } else if (payload.is_pos) {
          targetWebhook = env.POS_DISCORD_WEBHOOK_URL || env.DISCORD_WEBHOOK_URL;
        }

        if (!targetWebhook) {
          return jsonResponse({ ok: false, error: "Chưa cấu hình Discord Webhook" }, 400);
        }

        // Tập hợp toàn bộ file cần gửi
        const allFiles = [];

        // 1. Hóa đơn 72mm (luôn gửi đầu tiên)
        if (payload.receipt_base64) {
          const blobReceipt = base64ToBlob(payload.receipt_base64, "image/jpeg");
          if (blobReceipt) allFiles.push({ blob: blobReceipt, name: "hoa-don-72mm.jpg" });
        }

        // 2. Ảnh chấm công (nếu có)
        if (payload.image_base64) {
          const blobImg = base64ToBlob(payload.image_base64, "image/jpeg");
          if (blobImg) allFiles.push({ blob: blobImg, name: "anh-cham-cong.jpg" });
        }

        // 3. Danh sách ảnh/video không giới hạn từ máy POS
        if (Array.isArray(payload.media_list)) {
          payload.media_list.forEach((m, idx) => {
            const isVid = m.type === "video";
            const ext = isVid ? "mp4" : "jpg";
            const mime = isVid ? "video/mp4" : "image/jpeg";
            const blobMedia = base64ToBlob(m.dataUrl, mime);
            if (blobMedia) allFiles.push({ blob: blobMedia, name: "check-don-" + (idx + 1) + "." + ext });
          });
        }

        if (allFiles.length === 0) {
          await fetch(targetWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: payload.content, embeds: payload.embeds, allowed_mentions: { parse: [] } })
          });
        } else {
          // Chia chùm tối đa 9 tệp/lần gửi để tránh chạm trần giới hạn 10 tệp của Discord
          const CHUNK_SIZE = 9;
          for (let i = 0; i < allFiles.length; i += CHUNK_SIZE) {
            const chunk = allFiles.slice(i, i + CHUNK_SIZE);
            const formData = new FormData();

            if (i === 0) {
              // Tin nhắn đầu tiên chứa đầy đủ thông tin hóa đơn và embeds
              formData.append("payload_json", JSON.stringify({
                content: payload.content,
                embeds: payload.embeds,
                allowed_mentions: { parse: [] }
              }));
            } else {
              // Các đợt gửi sau chỉ báo tệp đính kèm tiếp theo
              formData.append("payload_json", JSON.stringify({
                content: `📎 *[Ảnh/Video bổ sung đợt ${Math.floor(i / CHUNK_SIZE) + 1}]*`
              }));
            }

            chunk.forEach((f, cIdx) => {
              formData.append("files[" + cIdx + "]", f.blob, f.name);
            });

            await fetch(targetWebhook, { method: "POST", body: formData });
          }
        }

        return jsonResponse({ ok: true });
      } catch (err) {
        return errResponse(err, "Không gửi được Discord");
      }
    }

    // 7. POS SYNC GOOGLE SHEET (cần đăng nhập, chỉ cho phép các thao tác POS)
    if (url.pathname === "/api/pos-sync" && request.method === "POST") {
      try {
        const user = await verifyToken(request, env);
        if (!user) return jsonResponse({ ok: false, error: "Chưa đăng nhập" }, 401);
        if (rateLimited(request, "possync", 120, 60 * 1000)) return jsonResponse({ ok: false, error: "Thao tác quá nhanh" }, 429);
        const body = await readJson(request, 50000);
        const action = String(body.action || "");
        let payload;
        if (action === "pos_sale") {
          const items = (Array.isArray(body.items) ? body.items : []).slice(0, 60).map(function (it) {
            return { type: it && it.type === "acc" ? "acc" : (it && it.type === "pleco" ? "pleco" : "fish"), name: cleanText(it && it.name, 120), size: cleanText(it && it.size, 40), qty: Math.floor(Number(it && it.qty)) || 0 };
          }).filter(function (it) { return it.name && it.qty > 0 && it.qty < 1000; });
          payload = {
            action: action,
            ma_don: cleanText(body.ma_don, 40), thoi_gian: vnNow(), nhan_vien: user.name,
            ten_khach: cleanText(body.ten_khach, 80), so_dien_thoai: cleanText(body.so_dien_thoai, 15),
            phuong_thuc_tt: cleanText(body.phuong_thuc_tt, 30), chi_tiet_sp: cleanText(body.chi_tiet_sp, 1500),
            tong_so_luong: Number(body.tong_so_luong) || 0, giam_gia: Number(body.giam_gia) || 0,
            phi_ship: Number(body.phi_ship) || 0, tong_tien: Number(body.tong_tien) || 0,
            ghi_chu: cleanText(body.ghi_chu, 300), items: items
          };
          if (!payload.ma_don || !items.length) return jsonResponse({ ok: false, error: "Đơn không hợp lệ" }, 400);
        } else if (action === "pos_checkin" || action === "pos_checkout") {
          payload = { action: action, so_dien_thoai: user.phone, ten_nhan_vien: user.name };
        } else if (action === "get_timesheet") {
          const m = String(body.thang_nam || "");
          payload = { action: action, thang_nam: /^\d{2}\/\d{4}$/.test(m) ? m : "", so_dien_thoai: user.phone, is_sep: user.role === "sep" };
        } else if (action === "today_stats") {
          if (user.role !== "sep") return jsonResponse({ ok: false, error: "Chỉ Sếp mới xem được doanh thu" }, 403);
          payload = { action: action };
        } else {
          return jsonResponse({ ok: false, error: "Thao tác không hợp lệ" }, 400);
        }
        const res = await callSheet(env, payload);
        const text = await res.text();
        let j;
        try { j = JSON.parse(text); } catch (e) {
          return jsonResponse({ ok: false, error: "Google Sheet không phản hồi đúng (Apps Script chưa Deploy phiên bản mới hoặc sai quyền truy cập)" }, 502);
        }
        if (j && j.ok === false && j.error === "unauthorized") {
          return jsonResponse({ ok: false, error: "SHEET_SECRET ở Cloudflare và Apps Script không khớp nhau" }, 502);
        }
        return jsonResponse(j);
      } catch (err) {
        return errResponse(err, "Không kết nối được Google Sheet");
      }
    }

    // 8. POS AUTH
    if (url.pathname === "/api/pos-auth" && request.method === "POST") {
      try {
        if (rateLimited(request, "pos_auth", 20, 60 * 1000)) {
          return jsonResponse({ ok: false, error: "Thao tác quá nhanh, vui lòng thử lại sau." }, 429);
        }
        const body = await readJson(request, 10000);
        const mode = body.mode;
        const phone = normalizePhone(body.phone);
        const pass = String(body.password || "").trim();
        const name = cleanText(body.name, 80);

        if (!isPhone(phone)) return jsonResponse({ ok: false, error: "Số điện thoại gồm 10 chữ số, bắt đầu bằng số 0." }, 400);
        if (pass.length < 4 || pass.length > 100) return jsonResponse({ ok: false, error: "Mật khẩu phải từ 4 ký tự trở lên." }, 400);
        if (!tokenSecret(env)) return jsonResponse({ ok: false, error: "Máy chủ chưa cấu hình SHEET_SECRET" }, 500);
        if (rateLimitedKey("auth:" + phone, 10, 10 * 60 * 1000)) {
          return jsonResponse({ ok: false, error: "Sai quá nhiều lần, vui lòng thử lại sau 10 phút." }, 429);
        }

        const docUrl = FS_BASE + "/nhan_vien/" + encodeURIComponent(phone);
        const getRes = await fsFetch(env, docUrl, { method: "GET" });

        if (mode === "register") {
          if (!env.POS_REGISTER_CODE) return jsonResponse({ ok: false, error: "Chưa bật đăng ký (thiếu POS_REGISTER_CODE trên máy chủ)." }, 403);
          if (!safeEqual(String(body.code || "").trim(), env.POS_REGISTER_CODE)) {
            return jsonResponse({ ok: false, error: "Mã đăng ký không đúng. Hãy hỏi chủ cửa hàng." }, 403);
          }
          if (getRes.ok) {
            return jsonResponse({ ok: false, error: "Số điện thoại này đã đăng ký! Hãy bấm Đăng nhập." }, 400);
          }
          if (name.length < 2) {
            return jsonResponse({ ok: false, error: "Vui lòng nhập họ và tên nhân viên." }, 400);
          }

          const checkRes = await fsFetch(env, FS_BASE + ":runQuery", {
            method: "POST",
            body: JSON.stringify({
              structuredQuery: { from: [{ collectionId: "nhan_vien" }], limit: 1 }
            })
          });
          const checkData = await checkRes.json();
          const hasAnyUser = Array.isArray(checkData) && checkData.some(function (x) { return x.document; });
          const role = hasAnyUser ? "nhan_vien" : "sep";

          const newUser = {
            phone: phone,
            name: name,
            password: await hashPassword(pass),
            role: role,
            created_at: new Date()
          };

          const createRes = await fsFetch(env, FS_BASE + "/nhan_vien?documentId=" + encodeURIComponent(phone), {
            method: "POST",
            body: JSON.stringify({ fields: toFsFields(newUser) })
          });

          if (!createRes.ok) return jsonResponse({ ok: false, error: "Không thể tạo tài khoản lúc này." }, 500);

          const u = { phone: phone, name: name, role: role };
          return jsonResponse({ ok: true, user: u, token: await signToken(env, u) });
        } else {
          if (!getRes.ok) {
            return jsonResponse({ ok: false, error: "Số điện thoại hoặc mật khẩu không đúng!" }, 400);
          }
          const docData = await getRes.json();
          const userData = fsFields(docData.fields || {});

          const chk = await checkPassword(userData.password, pass);
          if (!chk.ok) {
            return jsonResponse({ ok: false, error: "Số điện thoại hoặc mật khẩu không đúng!" }, 400);
          }
          if (chk.upgrade) {
            await fsFetch(env, docUrl + "?updateMask.fieldPaths=password", {
              method: "PATCH",
              body: JSON.stringify({ fields: { password: toFs(await hashPassword(pass)) } })
            }).catch(function () {});
          }

          const u = { phone: userData.phone || phone, name: userData.name || "Nhân viên", role: userData.role || "nhan_vien" };
          return jsonResponse({ ok: true, user: u, token: await signToken(env, u) });
        }
      } catch (err) {
        return errResponse(err, "Lỗi máy chủ, vui lòng thử lại");
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};

export default {
  async fetch(request, env) {
    return withSecurity(await handler.fetch(request, env));
  }
};
