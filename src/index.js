// Hàm tạo chữ ký HMAC-SHA256 theo chuẩn payOS
async function createSignature(dataStr, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(dataStr));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const DEFAULT_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1561567434861838446/eMtq9IqnPh_RUMCleTkvvMBKnrv5Z9K6JQn_PfBsI_DwUkWdVhW6j0uWBSPjFEQtwjQb";
const FIREBASE_PROJECT_ID = "tk-aqua";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store, no-cache, must-revalidate"
};

// Hàm tự động cập nhật trạng thái "Đã thanh toán" lên Firebase Firestore qua REST API
async function markOrderPaidInFirestore(orderCode) {
  try {
    const queryUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery`; const queryBody = { structuredQuery: { from: [{ collectionId: "don_hang" }], where: { fieldFilter: { field: { fieldPath: "ma_don" }, op: "EQUAL", value: { stringValue: `TKA-${orderCode}` }
          }
        },
        limit: 1
      }
    };

    const qRes = await fetch(queryUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(queryBody)
    });
    const qData = await qRes.json();

    if (Array.isArray(qData) && qData[0] && qData[0].document) {
      const docName = qData[0].document.name;
      const patchUrl = `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=trang_thai&updateMask.fieldPaths=paid`; await fetch(patchUrl, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fields: { trang_thai: { stringValue: "Đã thanh toán" }, paid: { booleanValue: true } } }) }); return true; } } catch (e) { console.error("Firestore update error:", e); } return false; }  export default { async fetch(request, env) { const url = new URL(request.url); const discordUrl = env.DISCORD_WEBHOOK_URL \vert{}\vert{} DEFAULT_DISCORD_WEBHOOK;  if (request.method === "OPTIONS") { return new Response(null, { headers: corsHeaders }); }  // 1. API GỬI THÔNG BÁO DISCORD (/api/notify) if (url.pathname === "/api/notify" && request.method === "POST") { try { const payload = await request.json(); await fetch(discordUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json", ...corsHeaders } }); } catch (err) { return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }); } }  // 2. API TẠO YÊU CẦU THANH TOÁN PAYOS (/api/create-payment) if (url.pathname === "/api/create-payment" && request.method === "POST") { try { const body = await request.json(); const orderCode = Number(body.orderCode); const amount = Number(body.amount); const description = String(body.description \vert{}\vert{} `TKA ${orderCode}`).slice(0, 25);
        const cancelUrl = "https://tkaqua.khanghuynh213671.workers.dev";
        const returnUrl = "https://tkaqua.khanghuynh213671.workers.dev";

        const signData = `amount=${amount}&cancelUrl=${cancelUrl}&description=${description}&orderCode=${orderCode}&returnUrl=${returnUrl}`; const signature = await createSignature(signData, env.PAYOS_CHECKSUM_KEY);  const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests", { method: "POST", headers: { "Content-Type": "application/json", "x-client-id": env.PAYOS_CLIENT_ID, "x-api-key": env.PAYOS_API_KEY }, body: JSON.stringify({ orderCode, amount, description, cancelUrl, returnUrl, signature }) });  const resData = await response.json(); return new Response(JSON.stringify(resData), { headers: { "Content-Type": "application/json", ...corsHeaders } }); } catch (err) { return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }); } }  // 3. API KIỂM TRA TRẠNG THÁI THANH TOÁN (/api/check-payment) if (url.pathname === "/api/check-payment" && request.method === "GET") { try { const orderCode = url.searchParams.get("orderCode"); const response = await fetch(`https://api-merchant.payos.vn/v2/payment-requests/${orderCode}`, {
          method: "GET",
          headers: {
            "x-client-id": env.PAYOS_CLIENT_ID,
            "x-api-key": env.PAYOS_API_KEY
          }
        });
        const resData = await response.json();

        // Nếu payOS báo PAID hoặc số tiền đã nhận đủ -> tự cập nhật luôn Firestore
        if (resData && resData.data && (resData.data.status === "PAID" || (resData.data.amountPaid > 0 && resData.data.amountPaid >= resData.data.amount))) {
          await markOrderPaidInFirestore(orderCode);
        }

        return new Response(JSON.stringify(resData), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }

    // 4. API NHẬN WEBHOOK TỪ PAYOS (/api/payos-webhook)
    if (url.pathname === "/api/payos-webhook" && request.method === "POST") {
      try {
        const webhookData = await request.json();
        if (webhookData.code === "00" && webhookData.data) {
          const { orderCode, amount, description } = webhookData.data;
          if (orderCode !== 123) {
            // 1. Tự động đổi trạng thái trên Firebase Firestore thành "Đã thanh toán"
            await markOrderPaidInFirestore(orderCode);

            // 2. Bắn thông báo về Discord
            await fetch(discordUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                content: `✅ **[WEBHOOK PAYOS] ĐƠN HÀNG #TKA-${orderCode} ĐÃ THANH TOÁN THÀNH CÔNG!**`, embeds: [{ title: `XÁC NHẬN THANH TOÁN #TKA-${orderCode}`, color: 5763719, fields: [ { name: "Số tiền thực nhận", value: `**${Number(amount).toLocaleString('vi-VN')} VNĐ**`, inline: true },
                    { name: "Nội dung CK", value: `\`${description || ''}\``, inline: true }
                  ],
                  footer: { text: "TK aqua · payOS Auto Webhook" }
                }]
              })
            });
          }
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
