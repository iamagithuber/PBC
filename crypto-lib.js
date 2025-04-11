// crypto-lib.js
const crypto = require("crypto");
const elliptic = require("elliptic");
const ec = new elliptic.ec("secp256k1");

// HMAC-SHA256(k, pw)
function F(k, pw) {
    const keyData = Buffer.from(k, 'utf-8');
    const messageData = Buffer.from(pw, 'utf-8');

    const hmac = crypto.createHmac('sha256', keyData);
    hmac.update(messageData);
    const signature = hmac.digest(); // returns a Buffer

    return new Uint8Array(signature); // match browser's Uint8Array return
}

// toValidPrivateKey 保持与前端一致
function toValidPrivateKey(rBuf) {
  const rHex = Array.from(rBuf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(""); // 模拟前端的 rHex 构造方式
  const key = ec.keyFromPrivate(rHex, "hex");
  const bn = key.getPrivate();
  return bn.toString(16).padStart(64, '0');
}

// 正确生成公钥
function KGenS(rBuf) {
  const privHex = toValidPrivateKey(rBuf);
  const keyPair = ec.keyFromPrivate(privHex, "hex");
  return keyPair.getPublic(false, "hex"); // uncompressed, 前缀 0x04
}

module.exports = { F, KGenS };
