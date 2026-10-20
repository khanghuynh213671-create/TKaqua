// Hàm tạo chữ ký HMAC-SHA256 theo chuẩn payOS
async function createSignature(dataStr, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(dataStr));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Xử lý CORS cho trình duyệt
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    // 1. API TẠO YÊU CẦU THANH TOÁN
    if (url.pathname === "/api/create-payment" && request.method === "POST") {
      try {
        const body = await request.json();
        const orderCode = Number(body.orderCode);
        const amount = Number(body.amount);
        const description = String(body.description || `TKA ${orderCode}`).slice(0, 25);
        const cancelUrl = "https://tkaqua.khanghuynh213671.workers.dev";
        const returnUrl = "https://tkaqua.khanghuynh213671.workers.dev";

        const signData = `amount=${amount}&cancelUrl=${cancelUrl}&description=${description}&orderCode=${orderCode}&returnUrl=${returnUrl}`;
        const signature = await createSignature(signData, env.PAYOS_CHECKSUM_KEY);

        const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-client-id": env.PAYOS_CLIENT_ID,
            "x-api-key": env.PAYOS_API_KEY
          },
          body: JSON.stringify({
            orderCode,
            amount,
            description,
            cancelUrl,
            returnUrl,
            signature
          })
        });

        const resData = await response.json();
        return new Response(JSON.stringify(resData), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { 
          status: 500,
          headers: { "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 2. API KIỂM TRA TRẠNG THÁI THANH TOÁN (Web tự động gọi kiểm tra)
    if (url.pathname === "/api/check-payment" && request.method === "GET") {
      try {
        const orderCode = url.searchParams.get("orderCode");
        const response = await fetch(`https://api-merchant.payos.vn/v2/payment-requests/${orderCode}`, {
          method: "GET",
          headers: {
            "x-client-id": env.PAYOS_CLIENT_ID,
            "x-api-key": env.PAYOS_API_KEY
          }
        });
        const resData = await response.json();
        return new Response(JSON.stringify(resData), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { 
          status: 500,
          headers: { "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // 3. API WEBHOOK DỰ PHÒNG TỪ PAYOS
    if (url.pathname === "/api/payos-webhook" && request.method === "POST") {
      try {
        const webhookData = await request.json();
        if (webhookData.code === "00" && webhookData.data) {
          const { orderCode, amount } = webhookData.data;
          if (env.DISCORD_WEBHOOK_URL) {
            await fetch(env.DISCORD_WEBHOOK_URL, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                content: `🔔 **ĐƠN HÀNG #TKA-${orderCode} ĐÃ THANH TOÁN THÀNH CÔNG!**\nSố tiền: **${amount.toLocaleString('vi-VN')}đ**`
              })
            });
          }
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 400 });
      }
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
