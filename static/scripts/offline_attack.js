// offline_attack.js

const fs = require("fs");
const readline = require("readline");
const { F, KGenS } = require("../../crypto-lib");

const kHex = "f93d68557716e06210e76464f9280357d506c4876587ef7059abcb7df884ba4c"; // 泄露的 k
const target_pk = "041df89489a95cf2a38b0cf2b88ef9a37c5cc5a47401f5adf056a3b1c3c0a41abccea6c258d30c5e5bc30316a7cdfc931267fc1f565c3c0e727b2aa60d36f5d370".toLowerCase(); // 用户 pk_sig

// 打开字典文件
const rl = readline.createInterface({
  input: fs.createReadStream("rockyou.txt", { encoding: "latin1" }),
  crlfDelay: Infinity
});

(async () => {
  console.log("[*] 正在运行离线爆破模拟...");

  for await (const line of rl) {
    const pw = line.trim();
    try {
      const r = F(kHex, pw);
      const pk = KGenS(r);

      if (pk && pk.toLowerCase() === target_pk) {
        console.log(`\n[❌] 破解成功！密码为：${pw}`);
        process.exit(0);
      }
      console.log(`\n[❌] 破解失败！密码为：${pw}`);
      console.log(`\n[❌] pk=${pk}`);
    } catch (err) {
      // 跳过异常输入
    }
  }

  console.log("\n[✅] 爆破失败，密码未被 rockyou.txt 覆盖。系统安全。");
})();
