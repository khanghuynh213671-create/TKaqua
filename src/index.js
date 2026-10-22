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

// Phí vận chuyển do SERVER quyết định (khớp với 3 lựa chọn trên web)
const SHIPPING = {
  "Nội thành TP.HCM (Hộp đóng hàng + Ship Grab/Ahamove)": 110000,
  "Tỉnh / Ngoại thành (Hộp đóng hàng + Xe khách)": 210000,
  "Quốc tế / Đi máy bay (Đóng gói chuyên dụng + Cước bay)": 500000
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

/* ================= Giới hạn tần suất (theo IP, trong bộ nhớ) ================= */
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

/* ================= Firestore (đăng nhập bằng Service Account) ================= */
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

/* ================= Bảng giá chuẩn từ Google Sheet ================= */
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

/* ================= Làm sạch dữ liệu khách ================= */
function cleanText(s, max) {
  return String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
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
async function createPayosLink(env, orderCode, amount) {
  const description = ("Than tang TK TKA-" + orderCode).slice(0, 25);
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

/* ================= Discord (chỉ khi đã thanh toán) ================= */
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

/* ================= Google Sheet (Apps Script + SHEET_SECRET) ================= */
async function callSheet(env, payload) {
  const sheetUrl = env.GOOGLE_SHEET_WEBHOOK_URL || DEFAULT_SHEET_WEBHOOK;
  await fetch(sheetUrl, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify(Object.assign({ secret: env.SHEET_SECRET || "" }, payload)),
    redirect: "follow"
  });
}

function updateSheetPaid(env, maDon) {
  return callSheet(env, { action: "paid", ma_don: maDon, tinh_trang: "Đã thanh toán" });
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
    thoi_gian: new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" }),
    ten_khach: order.ten_khach,
    so_dien_thoai: order.so_dien_thoai,
    dia_chi: order.dia_chi,
    chi_tiet_sp: chiTiet,
    chi_tiet_ca: chiTiet,
    tong_so_luong: order.tong_so_luong,
    tong_tien: order.tong_tien,
    ghi_chu: note + (order.phuong_thuc_ship || "Tiêu chuẩn")
  });
}

/* ================= Đánh dấu đã thanh toán (1 lần / đơn) ================= */
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
      console.error("Số tiền không khớp, đơn", orderCode, "cần", expected, "đã trả", paidAmount);
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
      notifyDiscordPaid(env.DISCORD_WEBHOOK_URL, order, orderCode).catch(function (e) { console.error("Discord error:", e); }),
      updateSheetPaid(env, "TKA-" + orderCode).catch(function (e) { console.error("Sheet error:", e); })
    ]);
    return true;
  } catch (e) {
    console.error("markOrderPaid error:", e);
  }
  return false;
}

/* ================= API ================= */
async function handleCreateOrder(request, env) {
  if (rateLimited(request, "order", 8, 10 * 60 * 1000)) {
    return jsonResponse({ error: "Bạn thao tác quá nhanh, vui lòng thử lại sau ít phút." }, 429);
  }
  const body = await request.json();
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
  let tienHang = 0, tongSoLuong = 0;
  for (const it of items) {
    const qty = Number(it.qty);
    if (!Number.isInteger(qty) || qty < 1 || qty > 999) return jsonResponse({ error: "Số lượng không hợp lệ" }, 400);
    const isAcc = it.type === "acc";
    const prod = findCatalogItem(isAcc ? catalogs[1] : catalogs[0], String(it.name || "").trim(), String(it.size || "").trim());
    if (!prod) return jsonResponse({ error: "Sản phẩm không còn trong danh mục: " + cleanText(it.name, 60) }, 400);
    if (qty > prod.stock) return jsonResponse({ error: "Sản phẩm \"" + prod.name + "\" không đủ hàng" }, 400);
    const thanhTien = prod.price * qty;
    tienHang += thanhTien;
    tongSoLuong += qty;
    lines.push({ loai: isAcc ? "Phụ kiện" : "Cá cảnh", ten_ca: prod.name, size: prod.size, so_luong: qty, don_gia: prod.price, thanh_tien: thanhTien });
  }

  const phiShip = SHIPPING[shipLabel];
  const tongTien = tienHang + phiShip;

  // Tạo mã đơn không trùng
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
  if (!createRes.ok) {
    console.error("Create order error:", await createRes.text());
    return jsonResponse({ error: "Không lưu được đơn hàng" }, 500);
  }

  // Tạo link thanh toán
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
      const patchRes = await fsFetch(env, FS_BASE + "/don_hang/" + encodeURIComponent("TKA-" + maSo) + "?updateMask.fieldPaths=payos", {
        method: "PATCH",
        body: JSON.stringify({ fields: { payos: toFs(payos) } })
      });
      if (!patchRes.ok) console.error("Save payos error:", await patchRes.text());
    }
  } catch (e) {
    console.error("payOS error:", e);
  }

  await createSheetRow(env, order, "TKA-" + maSo).catch(function (e) { console.error("Sheet error:", e); });

  const pub = publicOrder(Object.assign({}, order, { payos: payos }));
  // Chủ đơn vừa tạo -> trả đủ thông tin của chính họ
  pub.ten_khach = name; pub.so_dien_thoai = phone; pub.dia_chi = address;
  return jsonResponse({ ok: true, order: pub, payos: payos });
}

async function handleLookup(request, env) {
  if (rateLimited(request, "lookup", 20, 60 * 1000)) {
    return jsonResponse({ error: "Bạn tra cứu quá nhanh, vui lòng thử lại sau ít phút." }, 429);
  }
  const body = await request.json();
  const kw = cleanText(body && body.q, 40);
  if (!kw) return jsonResponse({ orders: [] });

  let docs = [];
  const phone = normalizePhone(kw);
  if (isPhone(phone)) {
    // Lấy rộng rồi tự sắp xếp theo ngày đặt (mới nhất trước) để không bị cắt mất đơn mới
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
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/api/create-order" && request.method === "POST") {
      try {
        return await handleCreateOrder(request, env);
      } catch (err) {
        console.error("create-order error:", err);
        return jsonResponse({ error: "Không thể tạo đơn lúc này" }, 500);
      }
    }

    if (url.pathname === "/api/lookup" && request.method === "POST") {
      try {
        return await handleLookup(request, env);
      } catch (err) {
        console.error("lookup error:", err);
        return jsonResponse({ error: "Không tra cứu được: " + String(err.message || err).slice(0, 600) }, 500);
      }
    }

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
          // Chỉ trả về những trường cần thiết
          return jsonResponse({ code: resData.code, data: { id: d.id, status: d.status, amount: d.amount, amountPaid: d.amountPaid } });
        }
        return jsonResponse({ code: resData.code, data: null });
      } catch (err) {
        return jsonResponse({ error: "Không kiểm tra được thanh toán" }, 500);
      }
    }

    if (url.pathname === "/api/payos-webhook" && request.method === "POST") {
      try {
        const webhookData = await request.json();
        const validSignature = await verifyPayosWebhook(webhookData, env.PAYOS_CHECKSUM_KEY);
        if (!validSignature) {
          return jsonResponse({ error: "Invalid signature" }, 401);
        }
        if (webhookData.code === "00" && webhookData.data) {
          const orderCode = webhookData.data.orderCode;
          if (orderCode !== 123) {
            await markOrderPaid(orderCode, env, webhookData.data.amount);
          }
        }
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Bad request" }, 400);
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
