'use strict'

import jwt from 'jsonwebtoken'
import base58 from 'bs58'
import crypto from 'crypto'



let serverSecret = base58.encode(crypto.randomBytes(32))

module.exports.setServerSecret = setServerSecret
module.exports.getSecret = getSecret
module.exports.auth = auth
module.exports.tryAuth = tryAuth
module.exports.parseToken = parseToken
module.exports.parseCachedToken = parseCachedToken
// Enable caching. This will increase performance x44000 times.
module.exports.cacheTokens = cacheTokens

let cacheSize = 0
let cachedTokens = new Map()

function setServerSecret(secret) {
  serverSecret = secret
}

// userSecret = sha512/256(serverSecret, userId).base58()
// 208k ops/sec
function getSecret(user) {
  // sha512/256
  let sha512 = crypto.createHash('sha512').update(serverSecret).update(user).digest()
  let sha256 = crypto.createHash('sha256').update(sha512).digest()
  return base58.encode(sha256)
}

// app.auth middleware
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
function tryAuth(req, res, next) {
  // Getting token from `Bearer $token`
  const token = req.headers.authorization?.split(' ').at(1)
  if (token) req.from = parseCachedToken(token)
  next()
}

function cacheTokens(size) {
  cacheSize = size
}

// up to 163m ops/sec
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

// 3717 ops/sec
function parseToken(token) {
  const decoded = jwt.decode(token)
  const user = decoded.user ?? decoded.sub
  if (!user) return
  const secret = getSecret(user)
  jwt.verify(token, secret)
  return user
}
