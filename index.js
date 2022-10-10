const https = require('https')
const crypto = require('crypto')

const url = 'api.simplepush.io'

exports.send = function({key, title, message, event, actions, password, salt}, err, feedbackCallback = null, feedbackCallbackTimeout = 60) {
    if (key == null || message == null) {
        return err(new SimplepushError("Key and message cannot be empty"))
    }

    if (Array.isArray(actions) && actions.length > 0) {
        if (typeof actions[0] === 'string') {
            if (!actions.every(a => (typeof a === "string"))) {
                return err(new SimplepushError("Feedback actions malformed"))
            }
        } else {
            if (!actions.every(a => a.hasOwnProperty('name') && a.hasOwnProperty('url'))) {
                return err(new SimplepushError("Get actions malformed"))
            }
        }
    }

    var data
    var encryptedActions

    if (password === undefined && salt === undefined) {
        data = JSON.stringify({
            key: key,
            title: title,
            msg: message,
            event: event,
            actions: actions
        })
    } else if (typeof password === 'string' && typeof salt === 'string') {
        const IV_LENGTH = 16
        var shasum = crypto.createHash('sha1')

        shasum.update(password + salt)
        let encryptionKeyBytes = Buffer.from(shasum.digest('hex').substring(0, 32), 'hex')

        let ivBytes = crypto.randomBytes(IV_LENGTH)

        var encrypt = ((data) => {
            if (data == null) {
                return null
            }

            let cipher = crypto.createCipheriv('aes-128-cbc', encryptionKeyBytes, ivBytes)
            cipher.setAutoPadding(true)
            let encrypted = cipher.update(data, 'utf8', 'base64')
            encrypted += cipher.final('base64')
            encryptedURLSafe = encrypted.replace(/\+/g, '-').replace(/\//g, '_')
            return encryptedURLSafe
        })

        var encryptActions = ((actions) => {
            if (actions == null) {
                return null
            }

            encrypted = []
            actions.forEach(function (action) {
                if (typeof action === 'string') {
                    // Feedback Action
                    encrypted.push(encrypt(action))
                } else if (action.hasOwnProperty('name') && action.hasOwnProperty('url')) {
                    // GET Action
                    let actionEncrypted = {
                        name: encrypt(action['name']),
                        url: encrypt(action['url'])
                    }

                    encrypted.push(actionEncrypted)
                }
            })
            return encrypted
        })

        let encryptedTitle = encrypt(title)
        let encryptedMessage = encrypt(message)
        encryptedActions = encryptActions(actions)

        data = JSON.stringify({
            key: key,
            title: encryptedTitle,
            msg: encryptedMessage,
            event: event,
            actions: encryptedActions,
            encrypted: 'true',
            iv: ivBytes.toString('hex')
        })
    } else {
        return err(new SimplepushError("Make sure to set both password and salt if you want to send an encrypted message"))
    }

    const options = {
        hostname: url,
        port: 443,
        path: '/send',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    }

    const req = https.request(options, res => {
        var body = ''
        res.on('data', function(chunk) {
            body += chunk
        })

        res.on('end', function() {
            const response = JSON.parse(body)
            if (response.feedbackId && feedbackCallback) {
                queryFeedbackEndpoint(response.feedbackId, actions, encryptedActions, feedbackCallbackTimeout, feedbackCallback, err)
            }
        })
    })

    req.on('error', error => {
        err(error)
    })

    req.write(data)
    req.end()
}

async function queryFeedbackEndpoint(feedbackId, actions, encryptedActions, timeout, callback, err) {
    var stop = false
    var n = 0
    var start = Date.now() / 1000 | 0
    const options = {
        hostname: url,
        port: 443,
        path: '/1/feedback/' + feedbackId,
        method: 'GET'
    }

    while (!stop) {
        const req = https.request(options, res => {
            var body = ''
            res.on('data', function(chunk) {
                body += chunk
            })

            res.on('end', function() {
                const r = JSON.parse(body)
                if (r.success && r.action_selected) {
                    stop = true

                    var selectedAction
                    if (encryptedActions == null) {
                        selectedAction = r.action_selected
                    } else {
                        let idx = encryptedActions.indexOf(r.action_selected)
                        selectedAction = actions[idx]
                    }

                    return callback({
                            actionSelected: selectedAction,
                            actionSelectedAt: r.action_selected_at,
                            actionDeliveredAt: r.action_delivered_at,
                            feedbackId: feedbackId
                        })
                } else if (!r.success) {
                    stop = true
                    return err(new SimplepushError(`Feedback ${feedbackId} expired or doesn't exist`))
                }
            })
        })

        req.on('error', error => {
            err(error)
        })

        req.end()

        if (timeout) {
            var now = Date.now() / 1000 | 0
            if (now > start + timeout) {
                stop = true
                return err(new SimplepushError("Action callback timeout for feedback " + feedbackId))
            }
        }

        if (n < 60) {
            // In the first minute query every second
            await wait(1000)
        } else if (n < 260) {
            // In the ten minutes after the first minute query every 3 seconds
            await wait(3000)
        } else {
            // After 11 minutes query every five seconds
            await wait(5000)
        }
    }
}

function wait(time) {
    return new Promise(resolve => {
        setTimeout(() => {
            resolve();
        }, time);
    });
}

function SimplepushError(message = "") {
    this.name = "SimplepushError";
    this.message = message;
}
SimplepushError.prototype = Error.prototype;