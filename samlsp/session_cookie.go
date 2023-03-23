package samlsp

import (
	"net"
	"time"

	"github.com/gofiber/fiber/v2"

	saml "github.com/meftunca/fiber-saml"
)

const defaultSessionCookieName = "token"

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite string
	MaxAge   time.Duration
	Codec    SessionCodec
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(ctx *fiber.Ctx, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}

	// ctx.Cookie( &fiber.Cookie{
	// 	Name:     c.Name,
	// 	Domain:   c.Domain,
	// 	Value:    value,
	// 	MaxAge:   int(c.MaxAge.Seconds()),
	// 	HTTPOnly: c.HTTPOnly,
	// 	Secure:   c.Secure || ctx.Secure(),
	// 	SameSite: c.SameSite,
	// 	Path:     "/",
	// })
	cookie := &fiber.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(c.MaxAge.Seconds()),
		HTTPOnly: c.HTTPOnly,
		Secure:   c.Secure || ctx.Secure(),
		SameSite: c.SameSite,
		Path:     "/",
	}
	ctx.Cookie(cookie)
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(ctx *fiber.Ctx) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	// cookie, err := r.Cookie(c.Name)
	cookie := ctx.Cookies(c.Name)

	if len(cookie) == 0 {
		return nil
	}
	newCookie := &fiber.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    "",
		MaxAge:   -1,
		HTTPOnly: c.HTTPOnly,
		Expires:  time.Unix(1, 0), // past time as close to epoch as possible, but not zero time.Time{}
		Secure:   c.Secure || ctx.Secure(),
		SameSite: c.SameSite,
		Path:     "/",
	}
	// cookie.Value = ""
	// cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	// cookie.Path = "/"
	// cookie.Domain = c.Domain
	// http.SetCookie(w, cookie)
	// Set the cookie
	ctx.Cookie(newCookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c CookieSessionProvider) GetSession(ctx *fiber.Ctx) (Session, error) {
	// cookie, err := r.Cookie(c.Name)
	cookie := ctx.Cookies(c.Name)
	if len(cookie) == 0 {
		return nil, ErrNoSession
	}

	session, err := c.Codec.Decode(cookie)
	if err != nil {
		return nil, ErrNoSession
	}
	return session, nil
}
