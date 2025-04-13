// 使用伪造的sk_sig来对（uid,m）进行签名，加密后得到伪造的τ（fake_token），进行攻击

async function simulateAttack() {
  const username = document.getElementById("username").value;
  const output = document.getElementById("result");
  output.textContent = "发起攻击中...";

  try {
    // 1. 获取 challenge
    const loginResp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });

    const loginData = await loginResp.json();
    if (!loginData.success) {
      output.textContent = `❌ 获取挑战失败：${loginData.error || '用户不存在或服务器错误'}`;
      return;
    }

    const challenge = loginData.challenge;
    console.log("服务器返回 challenge:", challenge);

    // 2. 构造伪造密钥和签名
    const fakeKey = crypto.getRandomValues(new Uint8Array(32));   // 模拟 sk_sig
    const fakeSig = crypto.getRandomValues(new Uint8Array(64));   // 模拟签名 sig(uid, challenge)

    // 构造伪 token（你系统设计中可能 token 是某种编码结构）
    const fakeSigStr = Array.from(fakeSig).map(b => String.fromCharCode(b)).join("");
    const fakeToken = btoa("fake:" + fakeSigStr);

    // 3. 请求验证伪 token
    const verifyResp = await fetch("/verify_fake_token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        challenge,
        fake_token: fakeToken
      })
    });

    const result = await verifyResp.json();

    // 4. 美化输出
    let outputText = `🧪 攻击尝试结果：\n\n`;
    outputText += `👤 用户名: ${username}\n`;
    outputText += `🔐 挑战值: ${challenge}\n`;
    outputText += `😈 伪 sk_sig (Base64):\n${btoa(String.fromCharCode(...fakeKey))}\n\n`;
    outputText += `🧾 伪造签名 (Base64):\n${btoa(String.fromCharCode(...fakeSig))}\n\n`;
    outputText += `📦 构造的伪 token:\n${fakeToken}\n\n`;

    if (result.success) {
      outputText += `❗️攻击成功！伪造 token 验证通过`;
    } else {
      outputText += `❌攻击失败：认证失败（符合强不可伪造性）`;
    }

    output.textContent = outputText;
  } catch (err) {
    output.textContent = `❌ 错误：${err.message}`;
  }
}

