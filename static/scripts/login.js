document.getElementById('loginForm').addEventListener('submit', async (e) => {

    e.preventDefault();
    const formData = new FormData(e.target);

    try {
        // 第一次（也是唯一一次）请求登录接口
        console.log("[Debug] try事件已触发");
        const response = await fetch('/login', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        console.log("[Debug] response事件已触发");
        if (data.success) {
            // 存储挑战消息（统一用 sessionStorage）
            sessionStorage.setItem('challenge', data.challenge);

            // 直接跳转，无需再次请求
            console.log("跳转至:", data.redirect); // 调试用
            window.location.href = data.redirect;
        } else {
            alert('登录失败: ' + (data.error || '未知错误'));
        }
    } catch (error) {
        console.error('请求失败:', error);
        alert('网络错误，请检查控制台输出');
    }
});