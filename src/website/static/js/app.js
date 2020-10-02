/* App JS file */

var formatDate = (date) => {
    let month = date.getMonth() + 1
    let minute = date.getMinutes()
    let day = date.getDate()

    if (day < 10) {
        day = '0' + day
    }

    if (month < 10) {
        month = '0' + month
    }

    if (minute < 10) {
        minute = '0' + minute
    }

    return day + '/' + month + '/' + date.getFullYear() + ' ' +
           date.getHours() + ':' + minute
}

$(document).ready(() => {
    $('#submit-tr').click((e) => {
        const $recipient = $('#recipient')
        const $amountGroup = $('#amount-grp')
        const $amount = $('#amount')
        const recipient = $recipient.val()
        const amount = parseFloat($amount.val(), 10)
        const el = e.currentTarget

        let valid = true

        $amountGroup.removeClass('has-danger')

        if (amount <= 0 || !Number.isInteger(amount)) {
            $amountGroup.addClass('has-danger')

            valid = false
        }

        e.preventDefault()
        $(el).prop('disabled', true)

        if (!valid) {
            return false
        }

        $.post('/transaction/new', { recipient, amount }).done(() => {
            window.notification.show('success', { msg: 'Transaction submitted' , dismiss: true })

            $amount.val('')
            $(el).prop('disabled', false)
        })
    })

    $.post('/account/get', {}).done((resp) => {
        const $balance = $('#balance-amount')

        $balance.html(resp.account.balance)

        const $tbody = $('#history > table > tbody')

        $tbody.empty()
        const history = resp.account.history

        Object.keys(history).reverse().forEach((k, i) => {
            const date = new Date(parseFloat(k) * 1000)

            const entity = history[k].name
            const amount = history[k].amount
            const label = history[k].label
            let amountStr = '<i class="ti-arrow-up"></i>'
            let amountTdCls = 'text-success'

            if (amount < 0) {
                amountStr = '<i class="ti-arrow-down"></i>'
                amountTdCls = 'text-danger'
            }

            if (i > 10) {
                return
            }

            const ts = Math.round(date.getTime() / 1000)

            $tbody.append('<tr><td class="tr-date" data-ts="' + ts + '">' + formatDate(date) + '</td><td>'+entity+'</td><td>'+label+'</td><td class="'+amountTdCls+'">' + amount + ' Q ' + amountStr  + '</td></tr>')
        })
    })

    if (window.BLOCKCHAIN_APP.email) {
        $.post('/users/list', { })
        .done((users) => {
            const $recipient = $('#recipient')

            $('#submit-tr').attr('disabled', !users.length)

            users.forEach((u) => {
                const html = `<option value="${ u.email }">${ u.name } (${ u.email })</option>`

                $recipient.append(html)
            })
        })

        $.post('/service/status', { })
        .done((response) => {
            response.statuses.forEach((s) => {
                const $el = $(`.service-item#${ s.key }`)

                $el.find('.service-status-up').toggleClass('hidden', s.status !== 'active')
                $el.find('.service-status-down').toggleClass('hidden', s.status !== 'sleeping')
            })
        })
    }

    $('.refresh-key').click(function(evt) {
        const key = $(this).data('key')

        $.post('/service/refresh-key', { key: key })
         .done((response) => {
            window.notification.show('success', { msg: 'Service key successfully refreshed' , dismiss: true })

            $(this).data('key', response.key)

            $(this).parents('.service-item').find('input').val(response.key)
        })

        evt.stopImmediatePropagation()

        return false
    })
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

/* Worker */
var wk = new Worker('/src/website/static/js/worker.js')

/* {{{ Worker scope */

var updateDropdown = function(hasNewTrs) {
    const dropdown = document.querySelector('#notificationDropdown')
    const content = document.querySelector('#notificationDropdownContent')
    const contentItem = content.getElementsByTagName('a') 
    const coll = dropdown.getElementsByTagName('span')

    /* No span yet & new tr */
    if (contentItem.length) {
        const span = document.createElement('span')
        span.classList = 'count'

        dropdown.append(span)
    } else {
        let i

        while (i = coll.item(0)) {
            i.remove()
        }
    }
}

var onTransactionData = function(data) {
    const header = document.querySelector('#notificationDropdownContent > .dropdown-header')

    data.lastTransactions.forEach((tr) => {
        const _d = new Date(tr.ts * 1000)
        const $a = $(`<a class="dropdown-item" href="#">
                        <div class="item-thumbnail">
                          <div class="item-icon">
                            <img src="/static/img/Qoin-recto-128.png">
                          </div>
                        </div>
                        <div class="item-content">
                          <h6 class="font-weight-normal">${ tr.amount } Qoins</h6>
                          <p class="font-weight-light small-text mb-0 text-muted">
                            ${ formatDate(_d) } 
                          </p>
                        </div>
                      </a>`)

        $a.click(function() {
            $(this).fadeOut(500, function() {
                $(this).remove()

                updateDropdown()
            })

            return false
        })

        header.insertAdjacentElement('afterend', $a[0])
    })

    updateDropdown()
}

/* }}} */

wk.onmessage = function(msg) {
    var scope = msg.data.scope

    if (typeof scope === 'undefined') {
        /* No scope defined, abort */
        return
    }

    switch (scope) {
      case 'tr':
        onTransactionData(msg.data.data)
        break
      default:
        console.error('Unhandled scope')
        return
    }
}

wk.postMessage({ route: 'start', data: {} })
