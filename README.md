# No Auth

## Zero Knowledge JWT Authorization: Secure Authentication without Storing User Accounts

The **Zero Knowledge JWT Authorization** package is a revolutionary Node.js package that offers a highly secure and privacy-focused approach to user authentication. By leveraging the power of Zero Knowledge Proof (ZKP) cryptography and JSON Web Tokens (JWT), this package allows developers to implement a robust authorization system without the need for storing user accounts on the server.

Traditional authentication systems require servers to store sensitive user account information, including passwords or hashed credentials. However, with the Zero Knowledge JWT Authorization package, this cumbersome and potentially vulnerable step is eliminated. Instead, the server generates unique cryptographic keys for each user during the registration process.

Utilizing Zero Knowledge Proof protocols, the generated keys never leave the client-side environment, ensuring that the server remains completely unaware of the user's credentials. This Zero Knowledge approach guarantees that user data is securely protected, even in the event of a server breach.

The package seamlessly integrates JSON Web Tokens (JWT) to facilitate secure and stateless authorization. The JWTs are generated and signed with the user's unique cryptographic keys. These tokens can then be securely transmitted between client and server for subsequent API requests, serving as proof of authentication.

With Zero Knowledge JWT Authorization, developers can confidently build applications that prioritize user privacy without compromising security. By eliminating the need for server-side storage of user accounts, potential attack vectors and data breaches are significantly reduced. Additionally, the package provides straightforward integration into existing Node.js projects, simplifying the development process.

## Key Features:
- Zero Knowledge Proof (ZKP) cryptography for secure user authentication
- JSON Web Tokens (JWT) for stateless authorization
- Eliminates the need for server-side storage of user accounts
- Enhanced security by preventing server-side data breaches
- Seamless integration into Node.js applications
- Developer-friendly API for easy implementation

Embrace a new era of authentication and prioritize user privacy with the **Zero Knowledge JWT Authorization** package. Say goodbye to the risks associated with storing user accounts on your server and empower your applications with a robust, secure, and privacy-centric authentication solution.

## Installation
``` sh
npm install --save @v57/noauth
```

## Usage
``` js
const { auth, getSecret, setServerSecret } = require('@v57/noauth')

// Setting server secret
// Will be stored globally, so auth middleware will be available in any file
setServerSecret('9HoB7GB9yGA5BUNeLe6aB1sx8Jm8PoAgE5gmiEiqTFmD')

// Starting server with auth/create and hello/authorized api
const app = express()
  .disable('x-powered-by').set("etag", false)
  .post('auth/create', (req, res) => {
    const user = newId(16)
    const secret = getSecret(user)
    res.json({ user, secret })
  }).post('hello/authorized', auth, (req, res) => {
    res.json({ message: 'hi', to: req.from })
  }).listen(8080)
```