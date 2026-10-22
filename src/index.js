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

/* ---- Kiểm tra chữ ký webhook payOS ---- */
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

const FIREBASE_PROJECT_ID = "tk-aqua";
const DEFAULT_SHEET_WEBHOOK = "https://script.google.com/macros/s/AKfycbwIvuLes3qi8AH3AINWDDzLPVigzNvp5kDLhYl0azjWWfqf3C2j9ynNSD4Wr7lzfpVvIg/exec";

const CATALOG_FISH_CSV = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQp8_YWn7P7HMP4k2JbLNI2gkrwATBP9zkJumK96bi2dwU8k2OM1AbAgAICyUayeZj4kqkro_nciT8N/pub?output=csv";
const CATALOG_ACC_CSV = "https://docs.google.com/spreadsheets/d/e/2PACX-1vQp8_YWn7P7HMP4k2JbLNI2gkrwATBP9zkJumK96bi2dwU8k2OM1AbAgAICyUayeZj4kqkro_nciT8N/pub?gid=1785201873&single=true&output=csv";

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

/* ---- Firestore REST helpers ---- */
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

/* ---- Bảng giá chuẩn từ Google Sheet (không tin giá do trình duyệt gửi) ---- */
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

async function loadPriceMap(csvUrl) {
  const res = await fetch(csvUrl, { cf: { cacheTtl: 60, cacheEverything: true } });
  const rows = parseCsvRows(await res.text());
  const map = {};
  if (rows.length < 2) return map;
  const head = rows[0].map(function (h) { return h.replace(/\s/g, ""); });
  const iName = head.findIndex(function (h) { return h === "TenCa" || h === "TenSP"; });
  const iPrice = head.indexOf("Gia");
  if (iName < 0 || iPrice < 0) return map;
  for (let r = 1; r < rows.length; r++) {
    const name = String(rows[r][iName] || "").trim();
    const price = parseInt(rows[r][iPrice], 10);
    if (name && price > 0) map[name] = price;
  }
  return map;
}

// Trả về tiền hàng chuẩn theo bảng giá, hoặc null nếu có món không hợp lệ
async function computeSubtotal(items) {
  if (!Array.isArray(items) || !items.length) return null;
  const maps = await Promise.all([loadPriceMap(CATALOG_FISH_CSV), loadPriceMap(CATALOG_ACC_CSV)]);
  let total = 0;
  for (const it of items) {
    const qty = Number(it.so_luong);
    if (!(qty > 0) || qty > 999 || Math.floor(qty) !== qty) return null;
    const map = it.loai === "Phụ kiện" ? maps[1] : maps[0];
    const price = map[String(it.ten_ca || "").trim()];
    if (!price) return null;
    total += price * qty;
  }
  return total;
}

async function findOrderDoc(orderCode) {
  const queryUrl = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents:runQuery";
  const qRes = await fetch(queryUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: "don_hang" }],
        where: { fieldFilter: { field: { fieldPath: "ma_don" }, op: "EQUAL", value: { stringValue: "TKA-" + orderCode } } },
        limit: 1
      }
    })
  });
  const qData = await qRes.json();
  if (Array.isArray(qData) && qData[0] && qData[0].document) return qData[0].document;
  return null;
}

/* ---- Thông báo Discord (chỉ khi đã thanh toán) ---- */
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

/* ---- Google Sheet (Apps Script, có mã bí mật SHEET_SECRET) ---- */
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

/* ---- Đánh dấu đã thanh toán (chỉ chạy 1 lần cho mỗi đơn) ---- */
async function markOrderPaid(orderCode, env, paidAmount) {
  try {
    const document = await findOrderDoc(orderCode);
    if (!document) return false;
    const fields = document.fields || {};

    // Đã thanh toán từ trước -> không làm lại, không thông báo lại
    const alreadyPaid =
      (fields.paid && fields.paid.booleanValue === true) ||
      (fields.trang_thai && fields.trang_thai.stringValue === "Đã thanh toán");
    if (alreadyPaid) return false;

    // Chỉ chấp nhận khi số tiền đã trả >= giá trị đơn
    const expected = fsValue(fields.tong_tien);
    if (!(Number(expected) > 0) || !(Number(paidAmount) >= Number(expected))) {
      console.error("Số tiền không khớp, đơn", orderCode, "cần", expected, "đã trả", paidAmount);
      return false;
    }

    const patchUrl = "https://firestore.googleapis.com/v1/" + document.name +
      "?updateMask.fieldPaths=trang_thai&updateMask.fieldPaths=paid" +
      "&currentDocument.updateTime=" + encodeURIComponent(document.updateTime);

    const patchRes = await fetch(patchUrl, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fields: {
          trang_thai: { stringValue: "Đã thanh toán" },
          paid: { booleanValue: true }
        }
      })
    });
    // Bị request khác ghi trước (precondition fail) -> bỏ qua để tránh gửi trùng
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/api/create-payment" && request.method === "POST") {
      try {
        const body = await request.json();
        const orderCode = Number(body.orderCode);
        if (!Number.isSafeInteger(orderCode) || orderCode <= 0) {
          return jsonResponse({ error: "Mã đơn không hợp lệ" }, 400);
        }

        // Lấy đơn thật từ Firestore, KHÔNG dùng số tiền do trình duyệt gửi
        const document = await findOrderDoc(orderCode);
        if (!document) return jsonResponse({ error: "Không tìm thấy đơn hàng" }, 404);
        const order = fsFields(document.fields || {});
        if (order.paid === true || order.trang_thai === "Đã thanh toán") {
          return jsonResponse({ error: "Đơn đã thanh toán" }, 409);
        }

        // Kiểm tra giá theo bảng giá hiện tại
        const subtotal = await computeSubtotal(order.san_pham);
        const phiShip = Number(order.phi_ship || 0);
        const amount = Number(order.tong_tien);
        if (subtotal === null || !(phiShip >= 0) || !(amount > 0) || amount < subtotal + phiShip) {
          return jsonResponse({ error: "Giá trị đơn hàng không hợp lệ" }, 400);
        }

        const description = ("Than tang TK TKA-" + orderCode).slice(0, 25);
        const cancelUrl = "https://tkaqua.khanghuynh213671.workers.dev";
        const returnUrl = "https://tkaqua.khanghuynh213671.workers.dev";

        const signData = "amount=" + amount + "&cancelUrl=" + cancelUrl + "&description=" + description + "&orderCode=" + orderCode + "&returnUrl=" + returnUrl;
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
            cancelUrl: cancelUrl,
            returnUrl: returnUrl,
            signature: signature
          })
        });

        const resData = await response.json();

        // Ghi đơn vào Google Sheet từ phía server (chỉ 1 lần khi tạo link thành công)
        if (resData && resData.data) {
          await createSheetRow(env, order, "TKA-" + orderCode).catch(function (e) { console.error("Sheet error:", e); });
        }
        return jsonResponse(resData);
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    if (url.pathname === "/api/check-payment" && request.method === "GET") {
      try {
        const orderCode = url.searchParams.get("orderCode");
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
        }

        return jsonResponse(resData);
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
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
        return jsonResponse({ error: err.message }, 400);
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
