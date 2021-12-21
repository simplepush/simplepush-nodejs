const https = require('https')
const crypto = require('crypto')

const options = {
    hostname: 'api.simplepush.io',
    port: 443,
    path: '/send',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    }
}

exports.send = function({key, title, message, event, password, salt}, err) {
    if (key == null || message == null) {
        return err(new Error("Key and message cannot be empty"))
    }

    var data

    if (password === undefined && salt === undefined) {
        data = JSON.stringify({
            key: key,
            title: title,
            msg: message,
            event: event
        })
    } else if (typeof password === 'string' && typeof salt === 'string') {
        const IV_LENGTH = 16
        var shasum = crypto.createHash('sha1')

        shasum.update(password + salt)
        let encryptionKeyBytes = Buffer.from(shasum.digest('hex').substring(0, 32), 'hex')

        let ivBytes = crypto.randomBytes(IV_LENGTH)

        var encrypt = ((data) => {
            if (data === null) {
                return null
            }

            let cipher = crypto.createCipheriv('aes-128-cbc', encryptionKeyBytes, ivBytes)
            cipher.setAutoPadding(true)
            let encrypted = cipher.update(data, 'utf8', 'base64')
            encrypted += cipher.final('base64')
            encryptedURLSafe = encrypted.replace('+', '-').replace('/', '_')
            return encryptedURLSafe
        })

        let encryptedTitle = encrypt(title)
        let encryptedMessage = encrypt(message)

        data = JSON.stringify({
            key: key,
            title: encryptedTitle,
            msg: encryptedMessage,
            event: event,
            encrypted: 'true',
            iv: ivBytes.toString('hex')
        })
    } else {
        return err(new Error("Make sure to set both password and salt if you want to send an encrypted message"))
    }

    const req = https.request(options, res => {
        res.on('close', function() {
            err()
        })
    })

    req.on('error', error => {
        err(error)
    })

    req.write(data)
    req.end()
}