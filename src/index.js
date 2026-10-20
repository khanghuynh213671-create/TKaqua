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

const DEFAULT_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1561567434861838446/eMtq9IqnPh_RUMCleTkvvMBKnrv5Z9K6JQn_PfBsI_DwUkWdVhW6j0uWBSPjFEQtwjQb";
const FIREBASE_PROJECT_ID = "tk-aqua";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store, no-cache, must-revalidate"
};

async function markOrderPaidInFirestore(orderCode) {
  try {
    const queryUrl = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents:runQuery";
    const queryBody = {
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
    };

    const qRes = await fetch(queryUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(queryBody)
    });
    const qData = await qRes.json();

    if (Array.isArray(qData) && qData[0] && qData[0].document) {
      const docName = qData[0].document.name;
      const patchUrl = "https://firestore.googleapis.com/v1/" + docName + "?updateMask.fieldPaths=trang_thai&updateMask.fieldPaths=paid";
      await fetch(patchUrl, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fields: {
            trang_thai: { stringValue: "Đã thanh toán" },
            paid: { booleanValue: true }
          }
        })
      });
      return true;
    }
  } catch (e) {
    console.error("Firestore update error:", e);
  }
  return false;
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...corsHeaders }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let discordUrl = DEFAULT_DISCORD_WEBHOOK;
    if (env.DISCORD_WEBHOOK_URL) {
      discordUrl = env.DISCORD_WEBHOOK_URL;
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/api/notify" && request.method === "POST") {
      try {
        const payload = await request.json();
        await fetch(discordUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        return jsonResponse({ ok: true });
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    if (url.pathname === "/api/create-payment" && request.method === "POST") {
      try {
        const body = await request.json();
        const orderCode = Number(body.orderCode);
        const amount = Number(body.amount);

        let rawDesc = "TKA " + orderCode;
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
          if (resData.data.status === "PAID") {
            await markOrderPaidInFirestore(orderCode);
          } else if (resData.data.amountPaid > 0 && resData.data.amountPaid >= resData.data.amount) {
            await markOrderPaidInFirestore(orderCode);
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
        if (webhookData.code === "00" && webhookData.data) {
          const orderCode = webhookData.data.orderCode;
          const amount = webhookData.data.amount;
          const description = webhookData.data.description;

          if (orderCode !== 123) {
            await markOrderPaidInFirestore(orderCode);

            let descText = "";
            if (description) {
              descText = description;
            }

            await fetch(discordUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                content: "✅ **[WEBHOOK PAYOS] ĐƠN HÀNG #TKA-" + orderCode + " ĐÃ THANH TOÁN THÀNH CÔNG!**",
                embeds: [{
                  title: "XÁC NHẬN THANH TOÁN #TKA-" + orderCode,
                  color: 5763719,
                  fields: [
                    { name: "Số tiền thực nhận", value: "**" + Number(amount).toLocaleString("vi-VN") + " VNĐ**", inline: true },
                    { name: "Nội dung CK", value: "`" + descText + "`", inline: true }
                  ],
                  footer: { text: "TK aqua · payOS Auto Webhook" }
                }]
              })
            });
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
