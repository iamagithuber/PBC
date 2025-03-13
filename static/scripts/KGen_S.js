const crypto = require('crypto');
const elliptic = require('elliptic');

// 选择 secp256k1 曲线
const ec = new elliptic.ec('secp256k1');

// 伪随机函数 F(k, pw) -> r
function deriveR(k, pw) {
    return crypto.createHmac('sha256', Buffer.from(k)).update(pw).digest();
}

// 确保 r 在合法私钥范围内
function toValidPrivateKey(r) {
    let bn = ec.keyFromPrivate(r).getPrivate();
    return bn.mod(ec.curve.n).toString(16);
}

// 生成密钥对
function generateKeyPair(k, pw) {
    let r = deriveR(k, pw);
    let privKey = toValidPrivateKey(r);
    let keyPair = ec.keyFromPrivate(privKey);
    return {
        sk_sig: privKey,
        pk_sig: keyPair.getPublic('hex')
    };
}


