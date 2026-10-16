var csrfToken = '';

// 同步获取 CSRF token
function getCsrfToken() {
    $.ajax({
        url: host_url + '/csrf-token',
        type: 'GET',
        async: false,
        success: function (data) {
            csrfToken = data.csrf_token;
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.error('Error fetching CSRF token:', textStatus, errorThrown);
        }
    });
}

// 在任何 AJAX 请求之前获取 CSRF token
getCsrfToken();

// 使用 ajaxPrefilter 全局设置 CSRF token
$.ajaxPrefilter(function (options, originalOptions, jqXHR) {
    jqXHR.setRequestHeader('X-CSRF-Token', csrfToken);
});