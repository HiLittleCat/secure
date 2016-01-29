/*
Package secure is a handler for the core (https://godoc.org/github.com/volatile/core).
It provides quick security wins.

Usage

Use adds the handler to the default handlers stack:

	secure.Use(nil)

Make sure to include the handler above any other handler that alter the response body.

See Options reference for custom settings.
*/
package secure
