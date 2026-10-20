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

    // BƯỚC 3: API TẠO YÊU CẦU THANH TOÁN (Frontend gọi lên)
    if (url.pathname === "/api/create-payment" && request.method === "POST") {
      try {
        const body = await request.json();
        const orderCode = Number(body.orderCode);
        const amount = Number(body.amount);
        const description = String(body.description || `TKA ${orderCode}`).slice(0, 25);
        const cancelUrl = "https://tkaqua.khanghuynh213671.workers.dev";
        const returnUrl = "https://tkaqua.khanghuynh213671.workers.dev";

        // Chuỗi dữ liệu sắp xếp theo alphabet để tạo chữ ký
        const signData = `amount=${amount}&cancelUrl=${cancelUrl}&description=${description}&orderCode=${orderCode}&returnUrl=${returnUrl}`;
        const signature = await createSignature(signData, env.PAYOS_CHECKSUM_KEY);

        // Gọi sang hệ thống payOS
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
          headers: { 
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
      }
    }

    // BƯỚC 4: API WEBHOOK NHẬN KẾT QUẢ TIỀN VỀ TỪ PAYOS
    if (url.pathname === "/api/payos-webhook" && request.method === "POST") {
      try {
        const webhookData = await request.json();
        
        // Kiểm tra giao dịch thành công (mã 00)
        if (webhookData.code === "00" && webhookData.data) {
          const { orderCode, amount } = webhookData.data;

          // Bắn thông báo về Discord (nếu có cấu hình DISCORD_WEBHOOK_URL trong Cloudflare Secrets)
          if (env.DISCORD_WEBHOOK_URL) {
            await fetch(env.DISCORD_WEBHOOK_URL, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                content: `✅ **ĐƠN HÀNG #TKA-${orderCode} ĐÃ THANH TOÁN THÀNH CÔNG!**\nSố tiền nhận: **${amount.toLocaleString('vi-VN')}đ**`
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

    // Trả về file tĩnh của web cho các route khác
    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
