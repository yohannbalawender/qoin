/* Worker responsible for interaction between the server and the clients */

var DELAY = 10000

/* Entry point */
var onmessage = function(e) {
    if (typeof e.data.route === 'undefined') {
        console.error('No route defined, abort')
        return
    }

    handleRoute(e.data)
}

var handleRoute = function(data) {
    switch (data.route) {
      case 'start':
        return onStart(data.data)
      default:
        console.error('Unknown route, abort')
        return
    }
}

var onStart = function() {
    setTimeout(requestLastTransaction, 0)
}

var requestLastTransaction = function() {
    const headers = new Headers()

    const params = { method: 'POST',
                     headers: headers,
                     mode: 'cors',
                     cache: 'default',
                     body: JSON.stringify({ since: (Date.now() - DELAY) / 1000 }) }

    fetch('/transaction/last', params)
        .then(function(response) {
            if (response.status !== 200) {
                throw new Error(response.statusText)
            }

            return response.json()
        })
        .then(function(data) {
            postMessage({ scope: 'tr', data: data })

            setTimeout(requestLastTransaction, DELAY)
        })
        .catch(function() {
            console.error('Unable to retrieve the last transactions')
        })
}
