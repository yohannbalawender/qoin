$(document).ready(() => {
    // const name = 'ndiaga.dieng@intersec.com'
    const name = 'yohann.balawender@intersec.com'
    // const name = 'jean-marc.coic@intersec.com'
    // const name = 'master@intersec.com'
    $.get('/account/get', { name }).done((resp) => {
        const $balance = $('#balance-amount')

        $balance.html(resp.account.balance)

        const $tbody = $('#history > table > tbody')

        $tbody.empty()
        const history = resp.account.history

        const formatDate = (date) => {
            let month = date.getMonth()
            let minute = date.getMinutes()

            if (month < 10) {
                month = '0' + month
            }

            if (minute < 10) {
                minute = '0' + minute
            }

            return date.getDate() + '/' + month + '/' + date.getFullYear() + ' ' +
                   date.getHours() + ':' + minute
        }

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

            $tbody.append('<tr><td>' + formatDate(date) + '</td><td>'+entity+'</td><td>'+label+'</td><td class="'+amountTdCls+'">' + amount + ' Q ' + amountStr  + '</td></tr>')
        })
    })
})
