var selectedServer = '';

function switchServer(serverName) {
    apiPost('/api/select-server', {server_name: serverName}, function(data) {
        selectedServer = serverName;
        var badge = document.getElementById('server-status-badge');
        if (badge) {
            badge.style.display = serverName ? 'inline-block' : 'none';
            badge.textContent = serverName ? 'Connected: ' + serverName : '';
            badge.className = 'badge-severity ' + (serverName ? 'badge-success' : 'badge-info');
        }
        toast('Switched to: ' + (serverName || 'local'), 'info');
        setTimeout(function() { location.reload(); }, 500);
    }, function() {
        toast('Failed to switch server', 'error');
    });
}

function apiPost(url, data, onSuccess, onError) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                var resp = JSON.parse(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300) {
                    if (onSuccess) onSuccess(resp);
                } else {
                    if (onError) onError(resp);
                    else toast(resp.error || 'Request failed', 'error');
                }
            } catch(e) {
                if (onError) onError({error: e.message});
                else toast('Request failed', 'error');
            }
        }
    };
    xhr.send(JSON.stringify(data));
}

function apiGet(url, onSuccess, onError) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                var resp = JSON.parse(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300) {
                    if (onSuccess) onSuccess(resp);
                } else {
                    if (onError) onError(resp);
                }
            } catch(e) {
                if (onError) onError({error: e.message});
            }
        }
    };
    xhr.send();
}

function toast(message, type) {
    type = type || 'info';
    var container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    var t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = message;
    container.appendChild(t);
    setTimeout(function() {
        t.style.opacity = '0';
        t.style.transform = 'translateX(100%)';
        t.style.transition = 'all 0.3s ease';
        setTimeout(function() { t.remove(); }, 300);
    }, 4000);
}

function formatTimestamp(ts) {
    if (!ts) return '';
    var d = new Date(ts * 1000);
    return d.toLocaleTimeString();
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.active').forEach(function(m) {
            m.classList.remove('active');
        });
    }
});
