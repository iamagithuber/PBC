const ec = new elliptic.ec('secp256k1');
let generatedKeys = {};

// 复制功能
document.addEventListener('click', async (e) => {
    if (e.target.closest('.copy-btn')) {
        const btn = e.target.closest('.copy-btn');
        const keyType = btn.dataset.key;
        const value = generatedKeys[keyType];

        try {
            btn.innerHTML = `<div class="loading"></div>`;
            await navigator.clipboard.writeText(value);
            btn.classList.add('copied');
            btn.innerHTML = `<i class="far fa-check"></i> 已复制`;
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.innerHTML = `<i class="far fa-copy"></i> 复制`;
            }, 2000);
        } catch (err) {
            console.error('复制失败:', err);
            btn.innerHTML = `<i class="far fa-times"></i> 复制失败`;
            setTimeout(() => {
                btn.innerHTML = `<i class="far fa-copy"></i> 复制`;
            }, 2000);
        }
    }
});

// 密钥生成逻辑
async function generateKeys() {
    const kArray = new Uint8Array(32);
    window.crypto.getRandomValues(kArray);
    const k = Array.from(kArray, b => b.toString(16).padStart(2, '0')).join('');
    const pw = document.getElementById('password').value;

    try {
        // 生成签名密钥secp256k1
        const { sk_sig, pk_sig } = await (async () => {
            const r = await deriveR(k, pw);
            const rHex = Array.from(r).map(b => b.toString(16).padStart(2, '0')).join('');
            const privKey = toValidPrivateKey(rHex);
            const keyPair = ec.keyFromPrivate(privKey, 'hex');
            return { sk_sig: privKey, pk_sig: keyPair.getPublic('hex') };
        })();

        // tweetnacl-js
        // 生成密钥对（Curve25519）
        const keyPair = nacl.box.keyPair();

        // 导出公钥和私钥为 Base64
        const publicKeyBase64 = btoa(String.fromCharCode(...keyPair.publicKey));
        const privateKeyBase64 = btoa(String.fromCharCode(...keyPair.secretKey));

        const pk_enc = publicKeyBase64;
        const sk_enc = privateKeyBase64;


        return { k, sk_sig, pk_sig, pk_enc, sk_enc };
    } catch (error) {
        console.error('密钥生成失败:', error);
        throw error;
    }
}

async function deriveR(k, pw) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(k);
    const messageData = encoder.encode(pw);

    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await window.crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        messageData
    );

    return new Uint8Array(signature);
}

function toValidPrivateKey(rHex) {
    const key = ec.keyFromPrivate(rHex, 'hex');
    const bn = key.getPrivate();
    const n = ec.curve.n;
    return bn.toString(16).padStart(64, '0');
}

// 表单提交处理
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = e.target.querySelector('button[type="submit"]');

    try {
        submitBtn.innerHTML = `<div class="loading"></div> 正在生成密钥...`;
        const keys = await generateKeys();

        generatedKeys = {
            k: keys.k,
            sk_sig: keys.sk_sig,
            pk_enc: keys.pk_enc
        };

        // 更新显示
        document.getElementById('displayK').textContent = keys.k;
        document.getElementById('displaySkSig').textContent = keys.sk_sig;
        document.getElementById('displayPkEnc').textContent = keys.pk_enc;
        document.getElementById('keyModal').style.display = 'flex';

        // 设置隐藏字段
        document.getElementById('pk_sig').value = keys.pk_sig;
        document.getElementById('secret_key').value = keys.k;
        document.getElementById('sk_enc').value = keys.sk_enc;
        document.getElementById('pk_enc').value = keys.pk_enc;

    } catch (error) {
        alert('密钥生成失败，请重试');
        console.error(error);
    } finally {
        submitBtn.innerHTML = `注册`;
    }
});

// 模态框控制
document.getElementById('confirmBtn').addEventListener('click', () => {
    document.getElementById('keyModal').style.display = 'none';
    document.getElementById('registerForm').submit();
});

document.getElementById('cancelBtn').addEventListener('click', () => {
    document.getElementById('keyModal').style.display = 'none';
    generatedKeys = {};
});