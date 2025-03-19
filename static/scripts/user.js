document.addEventListener('DOMContentLoaded', function() {
    // 获取并显示用户名
    const username = sessionStorage.getItem('username');
    if (!username) {
        window.location.href = '/login';
        return;
    }
    document.getElementById('usernameDisplay').textContent = `欢迎，${username}`;


});

function previewImage(event) {
    const reader = new FileReader();
    const preview = document.getElementById('preview');

    reader.onload = function() {
        preview.style.display = 'block';
        preview.src = reader.result;
    };

    if (event.target.files[0]) {
        reader.readAsDataURL(event.target.files[0]);
    }
}

function submitForm() {
    const bio = document.getElementById('bio').value;
    const avatar = document.getElementById('avatar').files[0];

    // 这里可以添加实际的表单提交逻辑
    console.log('提交信息:', { bio, avatar });
    alert('信息已保存！');
}

function logout() {
    // 清除会话数据
    sessionStorage.removeItem('username');

    // 调用后端注销接口
    fetch('/logout', {
        method: 'POST',
        credentials: 'same-origin'
    }).then(() => {
        window.location.href = '/login';
    });
}