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

/* ---- Cập nhật cột "Tình Trạng" trên Google Sheet ---- */
async function updateSheetPaid(env, maDon) {
  const sheetUrl = env.GOOGLE_SHEET_WEBHOOK_URL || DEFAULT_SHEET_WEBHOOK;
  await fetch(sheetUrl, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action: "paid", ma_don: maDon, tinh_trang: "Đã thanh toán" }),
    redirect: "follow"
  });
}

/* ---- Đánh dấu đã thanh toán (chỉ chạy 1 lần cho mỗi đơn) ---- */
async function markOrderPaid(orderCode, env) {
  try {
    const queryUrl = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents:runQuery";
    const qRes = await fetch(queryUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: "don_hang" }],
          where: {
            fieldFilter: {
              field: { fieldPath: "ma_don" },
              op: "EQUAL",
              value: { stringValue: "TKA-" + orderCode }
            }
          },
          limit: 1
        }
      })
    });
    const qData = await qRes.json();
    if (!(Array.isArray(qData) && qData[0] && qData[0].document)) return false;

    const document = qData[0].document;
    const fields = document.fields || {};

    // Đã thanh toán từ trước -> không làm lại, không thông báo lại
    const alreadyPaid =
      (fields.paid && fields.paid.booleanValue === true) ||
      (fields.trang_thai && fields.trang_thai.stringValue === "Đã thanh toán");
    if (alreadyPaid) return false;

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
        const amount = Number(body.amount);

        let rawDesc = "Than tang TK TKA-" + orderCode;
        if (body.description) {
          rawDesc = body.description;
        }
        const description = String(rawDesc).slice(0, 25);
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
            await markOrderPaid(orderCode, env);
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
            await markOrderPaid(orderCode, env);
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
