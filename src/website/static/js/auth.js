$(document).ready(() => {
    $('#submit-auth').click((e) => {
        const login = $('#login').val()
        const password = $('#pwd').val()

        $('form').find('.form-group').removeClass('has-danger');

        $.ajax({
            url: '/auth',
            type: 'POST',
            contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
            data: {
                'login': login,
                'password': password,
            },
            dataType: 'json',
            xhrFields: {
                withCredentials: true
            },
            crossDomain: true
        })
        .done(function(data) {
            document.location.href = '/';
        })
        .fail(function(err) {
            $('form').find('.form-group').addClass('has-danger');
        })

        e.preventDefault()
    })
})
