/*
Package secure is a handler for the core (https://godoc.org/github.com/volatile/core).
It provides quick security wins.

Make sure to include the handler above any other handler that alter the response body.

Usage

Use adds a handler to the default handlers stack:

	secure.Use(nil)
*/
package secure
