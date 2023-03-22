package samlsp

import (
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"

	"github.com/crewjam/saml"
)

// ErrorFunction is a callback that is invoked to return an error to the
// web user.
type ErrorFunction func(ctx *fiber.Ctx, err error)

// DefaultOnError is the default ErrorFunction implementation. It prints
// an message via the standard log package and returns a simple text
// "Forbidden" message to the user.
func DefaultOnError(ctx *fiber.Ctx, err error) {
	if parseErr, ok := err.(*saml.InvalidResponseError); ok {
		log.Printf("WARNING: received invalid saml response: %s (now: %s) %s",
			parseErr.Response, parseErr.Now, parseErr.PrivateErr)
	} else {
		log.Printf("ERROR: %s", err)
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
