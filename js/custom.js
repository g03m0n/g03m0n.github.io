document.addEventListener('DOMContentLoaded', function() {
    // Tìm tất cả các khối code
    document.querySelectorAll('.highlight').forEach(function(block) {
        // Tạo nút Copy
        var btn = document.createElement('button');
        btn.innerText = 'Copy';
        
        // Style cứng cho nút luôn để CSS theme không phá được
        Object.assign(btn.style, {
            position: 'absolute',
            top: '8px',
            right: '8px',
            padding: '4px 8px',
            fontSize: '12px',
            color: '#fff',
            backgroundColor: 'rgba(255, 255, 255, 0.2)',
            border: '1px solid rgba(255,255,255,0.4)',
            borderRadius: '4px',
            cursor: 'pointer',
            zIndex: '10',
            transition: 'all 0.2s'
        });

        // Hiệu ứng di chuột
        btn.onmouseover = function() { btn.style.backgroundColor = 'rgba(255, 255, 255, 0.4)'; }
        btn.onmouseout = function() { btn.style.backgroundColor = 'rgba(255, 255, 255, 0.2)'; }

        // Gắn nút vào khối code
        block.appendChild(btn);

        // Chức năng copy khi click
        btn.addEventListener('click', function() {
            var codeText = block.querySelector('code').innerText;
            navigator.clipboard.writeText(codeText).then(function() {
                btn.innerText = 'Copied!';
                btn.style.backgroundColor = '#28a745'; // Chuyển xanh lá
                btn.style.borderColor = '#28a745';
                setTimeout(function() { 
                    btn.innerText = 'Copy'; 
                    btn.style.backgroundColor = 'rgba(255, 255, 255, 0.2)';
                    btn.style.borderColor = 'rgba(255,255,255,0.4)';
                }, 2000);
            });
        });
    });
});