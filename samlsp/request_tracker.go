package samlsp

import (
	"github.com/gofiber/fiber/v2"
)

// RequestTracker tracks pending authentication requests.
//
// There are two main reasons for this:
//
//  1. When the middleware initiates an authentication request it must track the original URL
//     in order to redirect the user to the right place after the authentication completes.
//
//  2. After the authentication completes, we want to ensure that the user presenting the
//     assertion is actually the one the request it, to mitigate request forgeries.
type RequestTracker interface {
	// TrackRequest starts tracking the SAML request with the given ID. It returns an
	// `index` that should be used as the RelayState in the SAMl request flow.
	TrackRequest(ctx *fiber.Ctx, samlRequestID string) (index string, err error)

	// StopTrackingRequest stops tracking the SAML request given by index, which is a string
	// previously returned from TrackRequest
	StopTrackingRequest(ctx *fiber.Ctx, index string) error

	// GetTrackedRequests returns all the pending tracked requests
	GetTrackedRequests(ctx *fiber.Ctx) ([]TrackedRequest, error)

	// GetTrackedRequest returns a pending tracked request.
	GetTrackedRequest(ctx *fiber.Ctx, index string) (*TrackedRequest, error)
}

// TrackedRequest holds the data we store for each pending request.
type TrackedRequest struct {
	Index         string `json:"-"`
	SAMLRequestID string `json:"id"`
	URI           string `json:"uri"`
}

// TrackedRequestCodec handles encoding and decoding of a TrackedRequest.
type TrackedRequestCodec interface {
	// Encode returns an encoded string representing the TrackedRequest.
	Encode(value TrackedRequest) (string, error)

	// Decode returns a Tracked request from an encoded string.
	Decode(signed string) (*TrackedRequest, error)
}
