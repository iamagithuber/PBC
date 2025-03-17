const ec = new elliptic.ec('secp256k1');

// 工具函数：Base64转Uint8Array
function base64ToUint8Array(base64) {
return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
// 工具函数：Uint8Array转Base64
function uint8ArrayToBase64(bytes) {
return btoa(String.fromCharCode.apply(null, bytes));
}
function hexToBase64(hexString) {
  // 1. 检查 Hex 格式是否合法
  if (!/^[0-9a-fA-F]+$/.test(hexString)) {
    throw new Error("Invalid Hex string");
  }
  if (hexString.length % 2 !== 0) {
    throw new Error("Hex string length must be even");
  }
  // 2. 将 Hex 字符串转为字节数组
  const bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16));
  }
  // 3. 将字节数组转为 Base64
  const byteArray = new Uint8Array(bytes);
  const binaryString = String.fromCharCode(...byteArray);
  return btoa(binaryString);
}

document.getElementById('verifyForm').addEventListener('submit', async (e) => {
        e.preventDefault();
      try {
        // 从 sessionStorage 获取挑战值
        const challenge = sessionStorage.getItem('challenge');

        if (!challenge) {
            alert('错误：验证会话已过期，请重新登录');
            window.location.href = '/login';
            return;
        }

        // 构造提交数据
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const encrypt_key = document.getElementById('encrypt_key').value;
        const sign_key = document.getElementById('sign_key').value;
        const public_key = document.getElementById('public_key').value;


        // 拼接签名消息
        const rawData = `${username}${challenge}`;

        // 使用ECDSA签名（secp256k1）
        const msgHash = CryptoJS.SHA256(rawData).toString(CryptoJS.enc.Hex);
        const msgHashBytes = elliptic.utils.toArray(msgHash, 'hex'); // 转换为字节数组
        // 生成签名（自动规范化+DER编码）
        const keyPair = ec.keyFromPrivate(sign_key, 'hex');
        const signature = keyPair.sign(msgHashBytes, { canonical: true });

        const derSign = signature.toDER('hex'); // 最终需要的DER格式
        console.log("signature:",signature);
        console.log("derSign:",derSign);

        // 使用公钥加密签名结果
        const pk_enc = base64ToUint8Array(public_key);

        const derSign_base64 = hexToBase64(derSign);
        const derSign_8Array = base64ToUint8Array(derSign_base64);

        const encrypt_sigma = sealedBox.seal(derSign_8Array,pk_enc);
        const encrypt_sigma_base64 = uint8ArrayToBase64(encrypt_sigma);
        console.log("encrypt_sigma:",encrypt_sigma);
        console.log("encryptedData:",encrypt_sigma_base64);
        console.log("rawData:",rawData)
        console.log("signature:",signature)
        const response = await fetch('/verify1', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encryptedData: encrypt_sigma_base64,
                username: username
            })
        });

        console.log("[Debug] 事件已触发");
        // 处理响应
        const result = await response.json();

        if (result.success) {
            sessionStorage.removeItem('challenge');

            window.location.href = '/logout';
        } else {
            showAlert(`验证失败: ${result.error}`, 'danger');
        }
    } catch (error) {
        console.error('验证流程异常:', error);
        showAlert('系统错误，请稍后重试', 'danger');
    }
});


    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show mt-3`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.querySelector('.auth-card').prepend(alertDiv);
    }