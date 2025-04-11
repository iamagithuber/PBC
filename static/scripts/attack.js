// 使用伪造的sk_sig来对（uid,m）进行签名，加密后得到伪造的τ（fake_token），进行攻击
async function simulateAttack() {
  const username = document.getElementById("username").value;
  const output = document.getElementById("result");
  output.textContent = "发起攻击中...";

  // Step 1: 请求 /login 接口获取 challenge
  const loginResp = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  const loginData = await loginResp.json();
  if (!loginData.success) {
    output.textContent = "用户不存在或 challenge 获取失败";
    return;
  }

  const challenge = loginData.challenge;
  console.log("服务器返回 challenge:", challenge);

  // 构造伪 token（攻击者伪造）
  const fakeKey = crypto.getRandomValues(new Uint8Array(32));
  const fakeSig = crypto.getRandomValues(new Uint8Array(64));
  const fakeToken = btoa("fake:" + Array.from(fakeSig).map(b => String.fromCharCode(b)).join(""));

  // 请求后端验证伪造的 token
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
  output.textContent = result.success
    ? `✅攻击成功：伪造认证通过\n伪Token: ${fakeToken}`
    : `❌攻击失败：认证失败（符合强不可伪造性）\n伪Token: ${fakeToken}`;
}
