$(document).ready(() => {
    $('#submit-tr').click((e) => {
        const $recipient = $('#recipient')
        const $amountGroup = $('#amount-grp')
        const $amount = $('#amount')
        const recipient = $recipient.val()
        const amount = parseFloat($amount.val(), 10)

        let valid = true

        $amountGroup.removeClass('has-danger')

        if (amount <= 0 || !Number.isInteger(amount)) {
            $amountGroup.addClass('has-danger')

            valid = false
        }

        e.preventDefault()

        if (!valid) {
            return false
        }

        $.post('/transaction/new', { recipient, amount }).done(() => {
            window.notification.show('success', { msg: 'Transaction submitted' , dismiss: true })

            $amount.val('')
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
                let month = date.getMonth() + 1

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

    if (window.BLOCKCHAIN_APP.email) {
        $.post('/users/list', { })
        .done((users) => {
            var $recipient = $('#recipient')

            users.forEach((u) => {
                var html = `<option value="${ u.email }">${ u.name } (${ u.email })</option>`

                $recipient.append(html)
            })
        })
    }
})

var Notification = function() {
}

Notification.prototype = {
    success: function(options) {
        this.show('success', options)
    },

    info: function(options) {
        this.show('info', options)
    },

    warning: function(options) {
        this.show('warning', options)
    },
    
    danger: function(options) {
        this.show('danger', options)
    },

    renderMessages: function(msg) {
        if (typeof msg === 'string') {
            return '<p>' + msg + '</p>'
        } else
        if (typeof msg === 'object' && msg.length !== undefined) {
            return msg.map((m) => {
                return '<p>' + m + '</p>'
            })
        }
    },

    show: function(type, options) {
        var $ctn = $('.notification-ctn')

        if (!$ctn.length) {
            $ctn = $(
              '<div class="notification-ctn">' +
              '  <div class="notification-action">' +
              '    <div class="btn-push btn-push-default">' +
              '      <a href="#" title="Dismiss all" class="dismiss-all">' +
              '        <span class="inner">' +
              '          <i class="ti-close"></i>' +
              '        </span>' +
              '      </a>' +
              '    </div>' +
              '  </div>' +
              '</div>'
            );

            $ctn.find('.dismiss-all').click(this.onDismissAll.bind(this))

            this.$el = $ctn

            $('body').append($ctn)
        }

        var classType = 'alert alert-' + type
        var $el = $(
          '<div class="notification">' +
          '  <div class="' + classType + '">' +
          '    <a href="#" class="dismiss">' +
          '      <span class="ti-close"></span>' +
          '    </a>' +
              this.renderMessages(options.msg) +
          '  </div>' +
          '</div>'
        );

        if (type !== 'danger' && type !== 'warning') {
            _.delay(() => {
                $el.fadeOut(400, () => {
                    this.remove($el)
                })
            }, 5000)
        }

        $el.fadeIn()

        $el.find('.dismiss').click(() => {
            this.remove($el)
        })

        $ctn.show().append($el)

        this.toggleMultiple()
    },

    onDismissAll: function() {
        this.$el.find('.notification').each((i, el) => {
            this.remove($(el))
        })
    },

    remove: function($el) {
        $el.remove()

        this.$el.toggle(!!this.$el.find('.notification').length)

        this.toggleMultiple()
    },

    toggleMultiple: function() {
        this.$el.toggleClass('multiple', this.$el.find('.notification').length > 1)
    }
}

var notification = new Notification()

window.notification = notification
