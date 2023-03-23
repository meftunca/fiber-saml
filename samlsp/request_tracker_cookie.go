package samlsp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	saml "github.com/meftunca/fiber-saml"
)

var _RequestTracker = CookieRequestTracker{}

// CookieRequestTracker tracks requests by setting a uniquely named
// cookie for each request.
type CookieRequestTracker struct {
	ServiceProvider *saml.ServiceProvider
	NamePrefix      string
	Codec           TrackedRequestCodec
	MaxAge          time.Duration
	RelayStateFunc  func(ctx *fiber.Ctx) string
	SameSite        string
}

// TrackRequest starts tracking the SAML request with the given ID. It returns an
// `index` that should be used as the RelayState in the SAMl request flow.
func (t CookieRequestTracker) TrackRequest(ctx *fiber.Ctx, samlRequestID string) (string, error) {
	trackedRequest := TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(randomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           ctx.Request().URI().String(),
	}

	if t.RelayStateFunc != nil {
		relayState := t.RelayStateFunc(ctx)
		if relayState != "" {
			trackedRequest.Index = relayState
		}
	}

	signedTrackedRequest, err := t.Codec.Encode(trackedRequest)
	if err != nil {
		return "", err
	}

	cook := &fiber.Cookie{
		Name:     t.NamePrefix + trackedRequest.Index,
		Value:    signedTrackedRequest,
		MaxAge:   int(t.MaxAge.Seconds()),
		HTTPOnly: true,
		SameSite: t.SameSite,
		Secure:   t.ServiceProvider.AcsURL.Scheme == "https",
		Path:     t.ServiceProvider.AcsURL.Path,
	}
	ctx.Cookie(cook)

	return trackedRequest.Index, nil
}

// StopTrackingRequest stops tracking the SAML request given by index, which is a string
// previously returned from TrackRequest
func (t CookieRequestTracker) StopTrackingRequest(ctx *fiber.Ctx, index string) error {
	// cookie, err := r.Cookie(t.NamePrefix + index)
	cookie := ctx.Cookies(t.NamePrefix + index)
	if len(cookie) == 0 {
		return errors.New("no tracked request with index " + index)
	}
	newCookie := &fiber.Cookie{
		Name:     t.NamePrefix + index,
		Value:    "",
		MaxAge:   -1,
		HTTPOnly: true,
		SameSite: t.SameSite,
		Secure:   t.ServiceProvider.AcsURL.Scheme == "https",
		Path:     t.ServiceProvider.AcsURL.Path,
		Expires:  time.Unix(1, 0), // past time as close to epoch as possible, but not zero time.Time{}
	}
	ctx.Cookie(newCookie)

	return nil
}

// GetTrackedRequests returns all the pending tracked requests
func (t CookieRequestTracker) GetTrackedRequests(ctx *fiber.Ctx) []TrackedRequest {
	rv := []TrackedRequest{}
	// for _, cookie := range r.Cookies() {
	ctx.Request().Header.VisitAllCookie(func(key, value []byte) {
		cookie := string(value)
		if !strings.HasPrefix(cookie, t.NamePrefix) {
			return
		}

		trackedRequest, err := t.Codec.Decode(cookie)
		if err != nil {
			return
		}
		index := strings.TrimPrefix(cookie, t.NamePrefix)
		if index != trackedRequest.Index {
			return
		}

		rv = append(rv, *trackedRequest)
	})
	// for _, cookie := range ctx.Cookies() {

	// 	if !strings.HasPrefix(cookie.Name, t.NamePrefix) {
	// 		continue
	// 	}

	// 	trackedRequest, err := t.Codec.Decode(cookie.Value)
	// 	if err != nil {
	// 		continue
	// 	}
	// 	index := strings.TrimPrefix(cookie.Name, t.NamePrefix)
	// 	if index != trackedRequest.Index {
	// 		continue
	// 	}

	// 	rv = append(rv, *trackedRequest)
	// }
	return rv
}

// GetTrackedRequest returns a pending tracked request.
func (t CookieRequestTracker) GetTrackedRequest(ctx *fiber.Ctx, index string) (*TrackedRequest, error) {
	// cookie, err := r.Cookie(t.NamePrefix + index)
	cookie := ctx.Cookies(t.NamePrefix + index)
	if len(cookie) == 0 {
		return nil, errors.New("no tracked request with index " + index)
	}

	trackedRequest, err := t.Codec.Decode(cookie)
	if err != nil {
		return nil, err
	}
	if trackedRequest.Index != index {
		return nil, fmt.Errorf("expected index %q, got %q", index, trackedRequest.Index)
	}
	return trackedRequest, nil
}
