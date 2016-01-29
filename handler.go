package secure

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/volatile/core"
)

const (
	// HPKPDefaultMaxAge provides a default HPKP Max-Age value of 30 days.
	HPKPDefaultMaxAge = 30 * 24 * time.Hour
	// HSTSDefaultMaxAge provides a default HSTS Max-Age value of 30 days.
	HSTSDefaultMaxAge = 30 * 24 * time.Hour
	// HSTSPreloadMinAge is the lowest max age usable with HSTS preload. See https://hstspreload.appspot.com.
	HSTSPreloadMinAge = 10886400
)

// Options represents security options.
type Options struct {
	AllowedHosts []string     // AllowedHosts indicates which fully qualified domain names are allowed to point to this server. If none are set, all are allowed.
	CSP          string       // CSP contains Content Security Policy for responses. See http://www.w3.org/TR/CSP/ and https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_Content_Security_Policy.
	FrameAllowed bool         // FrameAllowed indicates whether the browsers can display the response in a frame, regardless of the site attempting to do so.
	HPKP         *HPKPOptions // HPKP contains the HTTP Public Key Pinning options.
	HSTS         *HSTSOptions // HPKP contains the HTTP Strict Transport Security options.
	SSLForced    bool         // SSLForced indicates whether an insecure request must be redirected to the secure protocol.
}

// HPKPOptions represents HTTP Public Key Pinning options.
// See RFC 7469 and https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning.
type HPKPOptions struct {
	Keys              []string      // Keys contains the Base64 encoded Subject Public Key Information (SPKI) fingerprints. This field is required.
	MaxAge            time.Duration // MaxAge indicates how long the browser should remember that this site is only to be accessed using one of the pinned keys. This field is required.
	IncludeSubdomains bool          // IncludeSubdomains indicates whether HPKP applies to all of the site's subdomains as well.
	ReportURI         string        // ReportURI is the URL at which validation failures are reported to.
}

// HSTSOptions represents HTTP Strict Transport Security options.
// See RFC 6797 and https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security.
type HSTSOptions struct {
	MaxAge            time.Duration // MaxAge indicates how long the browser should remember that this site is only to be accessed using HTTPS. This field is required.
	IncludeSubdomains bool          // IncludeSubdomains indicates whether HSTS applies to all of the site's subdomains as well.
	Preload           bool          // Preload indicates whether the browsers must use a secure connection. It's not a standard. See https://hstspreload.appspot.com.
}

// Use adds the handler to the default handlers stack.
func Use(options *Options) {
	// Panic when options are invalid.
	if options != nil {
		if options.HPKP != nil {
			if _, err := hpkpHeader(options); err != nil {
				panic(err)
			}
		}
		if options.HSTS != nil {
			if _, err := hstsHeader(options); err != nil {
				panic(err)
			}
		}
	}

	core.Use(func(c *core.Context) {
		if options != nil {
			if core.Production {
				// Check if host is allowed.
				if len(options.AllowedHosts) > 0 {
					for _, host := range options.AllowedHosts {
						if host == c.Request.URL.Host {
							goto SSLOptions
						}
					}
					http.NotFound(c.ResponseWriter, c.Request)
					return
				}

			SSLOptions:
				isSSL := (c.Request.URL.Scheme == "https" || c.Request.TLS != nil || c.Request.Header.Get("X-Forwarded-Proto") == "https")

				// If wanted, redirect permanently to the secure protocol.
				if !isSSL && options.SSLForced {
					url := c.Request.URL
					url.Scheme = "https"
					http.Redirect(c.ResponseWriter, c.Request, url.String(), http.StatusMovedPermanently)
					return
				}

				// Set HPKP header, but only if connected by SSL and the HPKP options are valid.
				if isSSL && options.HPKP != nil {
					if v, err := hpkpHeader(options); err != nil {
						panic(err)
					} else {
						c.ResponseWriter.Header().Set("Public-Key-Pins", v)
					}
				}

				// HSTS header, but only if HSTS options are valid.
				if options.HSTS != nil {
					if v, err := hstsHeader(options); err != nil {
						panic(err)
					} else {
						c.ResponseWriter.Header().Set("Strict-Transport-Security", v)
					}
				}
			}

			// Set Content Security Policy headers.
			if options.CSP != "" {
				c.ResponseWriter.Header().Set("Content-Security-Policy", options.CSP)
				c.ResponseWriter.Header().Set("X-Content-Security-Policy", options.CSP)
				c.ResponseWriter.Header().Set("X-WebKit-CSP", options.CSP)
			}
		}

		// If not explicitly allowed, displaying content inside a frame of a different origin is forbidden.
		if options == nil || !options.FrameAllowed {
			c.ResponseWriter.Header().Set("X-Frame-Options", "SAMEORIGIN")
		}

		// Set some "good practice" default headers.
		c.ResponseWriter.Header().Set("X-Content-Type-Options", "nosniff")
		c.ResponseWriter.Header().Set("X-XSS-Protection", "1; mode=block")

		c.Next()
	})
}

func hpkpHeader(o *Options) (v string, err error) {
	if len(o.HPKP.Keys) == 0 {
		err = errors.New("secure: at least one key must be set when using HPKP")
		return
	}

	if o.HPKP.MaxAge == 0 {
		err = errors.New("secure: max age must be set when using HPKP")
		return
	}

	for _, key := range o.HPKP.Keys {
		if v != "" {
			v += "; "
		}
		v += fmt.Sprintf("pin-sha256=%q", key)
	}

	v += fmt.Sprintf("; %.f", o.HPKP.MaxAge.Seconds())

	if o.HPKP.IncludeSubdomains {
		v += "; includeSubdomains"
	}

	if o.HPKP.ReportURI != "" {
		v += fmt.Sprintf("; report-uri=%q", o.HPKP.ReportURI)
	}

	return
}

func hstsHeader(o *Options) (v string, err error) {
	if !o.SSLForced {
		err = errors.New("secure: SSLForced must be true when using HSTS")
		return
	}

	if o.HSTS.MaxAge == 0 {
		err = errors.New("secure: max age must be set when using HSTS")
		return
	}

	if o.HSTS.Preload {
		if o.HSTS.MaxAge < HSTSPreloadMinAge {
			err = errors.New("secure: max age must be at least eighteen weeks when using HSTS preload")
			return
		}
		if !o.HSTS.IncludeSubdomains {
			err = errors.New("secure: subdomains must be included when using HSTS preload")
			return
		}
	}

	v += fmt.Sprintf("; %.f", o.HSTS.MaxAge.Seconds())

	if o.HSTS.IncludeSubdomains {
		v += "; includeSubdomains"
	}

	if o.HSTS.Preload {
		v += "; preload"
	}

	return
}
