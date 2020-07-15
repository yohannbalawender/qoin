$(document).ready(() => {
    $('#submit-tr').click((e) => {
        /* const $sender = $('.sender')
        const $recipient = $('.recipient')
        const $amount = $('.amount')

        const sender = $sender.find('input').val()
        const recipient = $recipient.find('input').val()
        const amount = parseFloat($amount.find('input').val(), 10) */

        const login = $('#sender').val()
        /* TODO: add password field */
        const password = $('#password').val()
        const recipient = $('#recipient').val()
        const amount = $('#amount').val()

        let valid = true

        /* $sender.removeClass('has-error')
        $recipient.removeClass('has-error')
        $amount.removeClass('has-error')

        $sender.find('.form-input-hint').addClass('hidden')
        $recipient.find('.form-input-hint').addClass('hidden')
        $amount.find('.form-input-hint').addClass('hidden') */

        /* if (!sender) {
            $sender.addClass('has-error')

            $sender.find('.form-input-hint')
                .removeClass('hidden')
                .html('Sender cannot be empty')

            valid = false
        }

        if (!recipient) {
            $recipient.addClass('has-error')

            $recipient.find('.form-input-hint')
                .removeClass('hidden')
                .html('Recipient cannot be empty')

            valid = false
        }

        if (amount <= 0) {
            $amount.addClass('has-error')

            $amount.find('.form-input-hint')
                .removeClass('hidden')
                .html('Amount cannot be null or negative')

            valid = false
        } */

        e.preventDefault()

        if (!valid) {
            return false
        }

        $.post('/transaction/new', { login, password, recipient, amount }).done(() => {
        })
    })

    $('#submit-account').click((e) => {
        const login = $('.account-name').find('input').val()

        const $info = $('.account-info')
        const $balance = $('.balance')

        $info.addClass('hidden')
        $balance.empty()

        $.post('/account/get', { }).done((resp) => {
            $info.removeClass('hidden')

            $balance.html(resp.account.balance)

            const $tbody = $('.account-info > table > tbody')

            $tbody.empty()
            const history = resp.account.history

            const formatDate = (date) => {
                let month = date.getMonth()

                if (month < 10) {
                    month = '0' + month
                }

                return date.getDate() + '/' + month + '/' + date.getFullYear() + ' ' +
                       date.getHours() + ':' + date.getMinutes()
            }

            Object.keys(history).forEach((k) => {
                const date = new Date(parseFloat(k) * 1000)

                $tbody.append('<tr><td>' + formatDate(date) + '</td><td>' + history[k] + '</td></tr>')
            })
        })

        e.preventDefault()
    })

    $.post('/users/list', { })
    .done((users) => {
        var $recipient = $('#recipient')

        users.forEach((u) => {
            var html = `<option value="${ u.email }">${ u.name } (${ u.email })</option>`

            $recipient.append(html)
        })
    })
})
