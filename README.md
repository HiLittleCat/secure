<p align="center"><img src="http://volatile.whitedevops.com/images/repositories/secure/logo.png" alt="Volatile Secure" title="Volatile Secure"><br><br></p>

Volatile Secure is a handler for the [Core](https://github.com/volatile/core).  
It implements a few quick security wins.

Make sure to include the handler above any other handler that alter the response body.

## Installation

```Shell
$ go get github.com/volatile/secure
```

## Usage [![GoDoc](https://godoc.org/github.com/volatile/secure?status.svg)](https://godoc.org/github.com/volatile/secure)

```Go
package main

import (
	"fmt"

	"github.com/volatile/core"
	"github.com/volatile/secure"
)

func main() {
	secure.Use(nil) // Some "good practice" default headers are set. See the secure.Options reference for specific options.

	core.Use(func(c *core.Context) {
		fmt.Fprint(c.ResponseWriter, "Hello, World!")
	})

	core.Run()
}
```

## Documentation

##### *Content Security Policy* (*CSP*)
  - [W3C official specification](http://www.w3.org/TR/CSP/)
  - [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_Content_Security_Policy)

##### *HTTP Public Key Pinning* (*HPKP*)
  - [RFC 7469](https://tools.ietf.org/html/rfc7469)
  - [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning)

##### *HTTP Strict Transport Security* (*HSTS*)
  - [RFC 6797](https://tools.ietf.org/html/rfc6797)
  - [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security)
  - [*HSTS* Preload](https://hstspreload.appspot.com)
