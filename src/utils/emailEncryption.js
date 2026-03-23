'use strict'
const crypto = require('crypto')

const algorithm = process.env.EMAIL_ID_ENCRYPTION_ALGORITHM
let secretKey
let fixedIV
try {
	secretKey = process.env.EMAIL_ID_ENCRYPTION_KEY ? Buffer.from(process.env.EMAIL_ID_ENCRYPTION_KEY, 'hex') : null
	fixedIV = process.env.EMAIL_ID_ENCRYPTION_IV ? Buffer.from(process.env.EMAIL_ID_ENCRYPTION_IV, 'hex') : null
} catch {
	secretKey = null
	fixedIV = null
}

const hasValidEncryptionConfig = () => {
	return Boolean(algorithm && secretKey && secretKey.length > 0 && fixedIV && fixedIV.length > 0)
}

/**
 * Returns true only if value looks like hex-encoded ciphertext (not plaintext email).
 */
function isProbablyHexCiphertext(value) {
	if (typeof value !== 'string' || !value) return false
	const trimmed = value.trim()
	if (trimmed.length === 0) return false
	// Plaintext email — never decrypt
	if (trimmed.includes('@')) return false
	if (!/^[0-9a-fA-F]+$/.test(trimmed)) return false
	if (trimmed.length % 2 !== 0) return false
	return true
}

const encrypt = (plainTextEmail) => {
	if (!hasValidEncryptionConfig()) {
		throw new Error('Email encryption is not configured (missing EMAIL_ID_ENCRYPTION_* env vars)')
	}
	try {
		const cipher = crypto.createCipheriv(algorithm, secretKey, fixedIV)
		return cipher.update(plainTextEmail, 'utf-8', 'hex') + cipher.final('hex')
	} catch (err) {
		console.log(err)
		throw err
	}
}

/**
 * Decrypts stored email/phone hex ciphertext.
 * If the value is legacy plaintext, invalid hex, wrong length for AES, wrong key, or corrupted,
 * returns the original string instead of throwing (avoids ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH in search/list APIs).
 */
const decrypt = (encryptedEmail) => {
	if (encryptedEmail == null || encryptedEmail === '') {
		return encryptedEmail
	}
	const value = typeof encryptedEmail === 'string' ? encryptedEmail.trim() : String(encryptedEmail).trim()
	if (value === '') {
		return encryptedEmail
	}
	if (value.includes('@')) {
		return value
	}
	if (!hasValidEncryptionConfig()) {
		console.warn('emailEncryption.decrypt: encryption not configured, returning value as-is')
		return value
	}
	if (!isProbablyHexCiphertext(value)) {
		return value
	}
	try {
		const decipher = crypto.createDecipheriv(algorithm, secretKey, fixedIV)
		return decipher.update(value, 'hex', 'utf-8') + decipher.final('utf-8')
	} catch (err) {
		console.warn(
			'emailEncryption.decrypt: failed (wrong key/IV/algorithm, corrupted data, or legacy plaintext). Returning original.',
			err.message
		)
		return value
	}
}

const emailEncryption = { encrypt, decrypt }

module.exports = emailEncryption
