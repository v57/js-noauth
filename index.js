'use strict'
const jwt = require('jsonwebtoken')
const base58 = require('bs58')
const crypto = require('crypto')

// Exported functions

module.exports.setServerSecret = setServerSecret
module.exports.getSecret = getSecret
module.exports.auth = auth
module.exports.tryAuth = tryAuth
module.exports.parseToken = parseToken
module.exports.parseCachedToken = parseCachedToken
module.exports.cacheTokens = cacheTokens

// Stored values

let serverSecret = base58.encode(crypto.randomBytes(32))
let cacheSize = 0
let cachedTokens = new Map()

// Main functions

/**
 * @abstract Sets server secret. Should be called before any other function.
 * @param {string} secret
 */
function setServerSecret(secret) {
  serverSecret = secret
}

/**
 * userSecret = sha512/256(serverSecret, userId).base58()
 * @abstract Generates user secret from server secret and user id.
 * @description Algorithm: userSecret = sha512/256(serverSecret, userId).base58()
 *
 * Performance: 208k ops
 * @param {string} user
 */
function getSecret(user) {
  // sha512/256
  let sha512 = crypto.createHash('sha512').update(serverSecret).update(user).digest()
  let sha256 = crypto.createHash('sha256').update(sha512).digest()
  return base58.encode(sha256)
}

// app.auth middleware
/**
 * @abstract Authorization Middleware for express.js
 * @description Will put user id to `req.from` if token is valid. Will return 401 if token is not provided. Will return 403 if token is invalid.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function auth(req, res, next) {
  // Getting token from `Bearer $token`
  const token = req.headers.authorization?.split(' ').at(1)
  if (!token) return res.sendStatus(401)
  // Parsing token
  const user = parseCachedToken(token)
  if (!user) return res.sendStatus(403)
  req.from = user
  next()
}

/**
 * @abstract Optional Authorization Middleware for express.js
 * @description Will put user id to `req.from` if token is valid.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function tryAuth(req, res, next) {
  // Getting token from `Bearer $token`
  const token = req.headers.authorization?.split(' ').at(1)
  if (token) req.from = parseCachedToken(token)
  next()
}

/**
 * @abstract Sets cache size. Should be called before any other function. 0 - disable caching.
 * @description Caching will increase performance x44000 times.
 * @param {number} size
 */
function cacheTokens(size) {
  cacheSize = size
}

// up to 163m ops/sec
/**
 * @abstract Looks for token in cache. If not found, parses token and caches it.
 * @description Performance: up to 163m ops on m1 mac
 * @param {string} token
 * @returns { string | undefined }
 */
function parseCachedToken(token) {
  if (cacheSize == 0) return parseToken(token)
  let user = cachedTokens.get(token)
  if (user) return user
  user = parseToken(token)
  if (!user) return
  if (cachedTokens.size > cacheSize) cachedTokens.clear()
  cachedTokens.set(token, user)
  return user
}

/**
 * @abstract Parses token. Will return user id if token is valid. Will return undefined if token is invalid.
 * @description Performance: 3717 ops on m1 mac
 * @param {string} token
 * @returns { string | undefined }
 */
function parseToken(token) {
  const decoded = jwt.decode(token)
  const user = decoded.user ?? decoded.sub
  if (!user) return
  const secret = getSecret(user)
  jwt.verify(token, secret)
  return user
}
