        console.log("[Debug] verify事件已进入");
document.getElementById('verifyForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        // 获取 session 中的挑战
        const challenge = sessionStorage.getItem('challenge');
        if (!challenge) {
            alert('错误：验证会话已过期，请重新登录');
            window.location.href = '/login';
            return;
        }

        // 构造提交数据
        const payload = {
            challenge: challenge,
            password: document.getElementById('password').value,
            encrypt_key: document.getElementById('encrypt_key').value,
            sign_key: document.getElementById('sign_key').value,
            public_key: document.getElementById('public_key').value,
        };

        try {
            const response = await fetch('/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.success) {
                sessionStorage.removeItem('challenge');  // 清除挑战
                window.location.href = '/dashboard';  // 跳转到仪表盘
            } else {
                showAlert('验证失败: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('验证请求失败:', error);
            showAlert('网络连接异常，请重试', 'danger');
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