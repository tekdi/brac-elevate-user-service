'use strict'
const crypto = require('crypto')

const secretKey = Buffer.from(process.env.EMAIL_ID_ENCRYPTION_KEY, 'hex')
const fixedIV = Buffer.from(process.env.EMAIL_ID_ENCRYPTION_IV, 'hex')
const algorithm = process.env.EMAIL_ID_ENCRYPTION_ALGORITHM

const encrypt = (plainTextEmail) => {
	try {
		const cipher = crypto.createCipheriv(algorithm, secretKey, fixedIV)
		return cipher.update(plainTextEmail, 'utf-8', 'hex') + cipher.final('hex')
	} catch (err) {
		console.log(err)
		throw err
	}
}

const decrypt = (encryptedEmail) => {
	try {
		const decipher = crypto.createDecipheriv(algorithm, secretKey, fixedIV)
		return decipher.update(encryptedEmail, 'hex', 'utf-8') + decipher.final('utf-8')
	} catch (err) {
		console.log(err)
		throw err
	}
}

/** When phone_code is empty, legacy plaintext is returned as-is; otherwise decrypt is used. */
const decryptPhone = (phoneValue, phoneCode) => {
	if (!phoneValue || typeof phoneValue !== 'string') {
		return phoneValue
	}
	const hasCode = phoneCode != null && String(phoneCode).trim() !== ''
	if (!hasCode) {
		return phoneValue
	}
	return decrypt(phoneValue)
}

const emailEncryption = { encrypt, decrypt, decryptPhone }

module.exports = emailEncryption
