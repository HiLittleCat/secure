/*
Package secure is a handler for the Core (https://github.com/volatile/core).
It implements a few quick security wins.

Make sure to include the handler above any other handler that alter the response body.

Usage

Example:

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

Documentation

Content Security Policy (CSP): http://www.w3.org/TR/cors/, https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_Content_Security_Policy

HTTP Public Key Pinning (HPKP): RFC 7469, https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning

HTTP Strict Transport Security (HSTS): RFC 6797, https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security, https://hstspreload.appspot.com
*/
package secure
