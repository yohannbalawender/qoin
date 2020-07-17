/* Worker responsible for interaction between the server and the clients */

/* Entry point */
var onmessage = function(e) {
    postMessage('Message forwarded')

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
    setTimeout(requestLastTransaction, 5000)
}

var requestLastTransaction = function() {
    fetch('/')
}
