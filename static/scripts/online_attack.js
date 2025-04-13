document.addEventListener("DOMContentLoaded", function () {
  const button = document.querySelector("form button");
  button.addEventListener("click", startAttack);
});

async function startAttack() {
  const username = document.getElementById("username").value;
  const resultDiv = document.getElementById("result");
  resultDiv.innerHTML = "🚀 正在发起攻击...";

  try {
    // 获取挑战
    const loginResp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });
    const loginData = await loginResp.json();

    if (!loginData.success) {
      const reason = loginData.error || "无法获取挑战";
      throw new Error(`获取挑战失败：${reason}`);
    }

    const challenge = loginData.challenge;

    // 获取用户加密公钥
    const userResp = await fetch("/get_user_info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });
    const userData = await userResp.json();
    if (!userData.success) throw new Error("用户信息不存在");

    const pkEncBase64 = userData.pk_enc;
    const pkEncBytes = nacl.util.decodeBase64(pkEncBase64);

    // 伪造签名
    const fakeSignature = nacl.randomBytes(64); // 模拟签名
    const fakeSignatureBase64 = btoa(String.fromCharCode(...fakeSignature));

    // 封装成加密 token
    const sealed = sealedBoxEncrypt(pkEncBytes, fakeSignature);
    const encryptedDataBase64 = nacl.util.encodeBase64(sealed);

    // 提交验证
    const verifyRes = await fetch("/verify_fake_token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        encryptedData: encryptedDataBase64
      })
    });

    const verifyResult = await verifyRes.json();

    // 展示信息
    let output = `🧪 攻击尝试结果：\n\n`;
    output += `👤 用户名: ${username}\n`;
    output += `🔐 挑战值: ${challenge}\n`;
    output += `🧾 伪造签名 (Base64):\n${fakeSignatureBase64}\n\n`;
    output += `📦 构造的伪token (encryptedData):\n${encryptedDataBase64}\n\n`;

    if (verifyResult.success) {
      output += "❗️攻击成功！伪造 token 被接受";
    } else {
      output += "❌攻击失败：认证失败（符合在线不可伪造性）️";
    }

    resultDiv.innerText = output;
  } catch (err) {
    resultDiv.innerText = `❌ 错误：${err.message}`;
  }
}

// 模拟 SealedBox 加密
function sealedBoxEncrypt(recipientPublicKey, message) {
  const ephKeyPair = nacl.box.keyPair();
  const nonce = nacl.randomBytes(24);
  const boxed = nacl.box(message, nonce, recipientPublicKey, ephKeyPair.secretKey);

  const sealed = new Uint8Array(32 + 24 + boxed.length);
  sealed.set(ephKeyPair.publicKey, 0);
  sealed.set(nonce, 32);
  sealed.set(boxed, 56);
  return sealed;
}
