package samlsp

import (
	"encoding/xml"
	"net/http"

	"github.com/gofiber/fiber/v2"
	saml "github.com/meftunca/fiber-saml"
)

// Middleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /saml/metadata and /saml/acs, respectively.
//
// It also provides middleware RequireAccount which redirects users to
// the auth process if they do not have session credentials.
//
// When redirecting the user through the SAML auth flow, the middleware assigns
// a temporary cookie with a random name beginning with "saml_". The value of
// the cookie is a signed JSON Web Token containing the original URL requested
// and the SAML request ID. The random part of the name corresponds to the
// RelayState parameter passed through the SAML flow.
//
// When validating the SAML response, the RelayState is used to look up the
// correct cookie, validate that the SAML request ID, and redirect the user
// back to their original URL.
//
// Sessions are established by issuing a JSON Web Token (JWT) as a session
// cookie once the SAML flow has succeeded. The JWT token contains the
// authenticated attributes from the SAML assertion.
//
// When the middleware receives a request with a valid session JWT it extracts
// the SAML attributes and modifies the http.Request object adding a Context
// object to the request context that contains attributes from the initial
// SAML assertion.
//
// When issuing JSON Web Tokens, a signing key is required. Because the
// SAML service provider already has a private key, we borrow that key
// to sign the JWTs as well.
type Middleware struct {
	ServiceProvider saml.ServiceProvider
	OnError         func(ctx *fiber.Ctx, err error)
	Binding         string // either saml.HTTPPostBinding or saml.HTTPRedirectBinding
	ResponseBinding string // either saml.HTTPPostBinding or saml.HTTPArtifactBinding
	RequestTracker  RequestTracker
	Session         SessionProvider
}

// ServeHTTP implements http.Handler and serves the SAML-specific HTTP endpoints
// on the URIs specified by m.ServiceProvider.MetadataURL and
// m.ServiceProvider.AcsURL.
func (m *Middleware) ServeHTTP(ctx *fiber.Ctx) error {
	// if r.URL.Path == m.ServiceProvider.MetadataURL.Path {
	if ctx.Path() == m.ServiceProvider.MetadataURL.Path {
		m.ServeMetadata(ctx)
		return nil
	}

	// if r.URL.Path == m.ServiceProvider.AcsURL.Path {
	if ctx.Path() == m.ServiceProvider.AcsURL.Path {
		m.ServeACS(ctx)
		return nil
	}

	// http.NotFoundHandler().ServeHTTP(ctx)
	return ctx.Status(http.StatusNotFound).SendString("Not Found")
}

// ServeMetadata handles requests for the SAML metadata endpoint.
func (m *Middleware) ServeMetadata(ctx *fiber.Ctx) error {
	buf, _ := xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	// w.Header().Set("Content-Type", "application/samlmetadata+xml")
	ctx.Set("Content-Type", "application/samlmetadata+xml")
	// w.Write(buf)
	return ctx.Send(buf)
}

// ServeACS handles requests for the SAML ACS endpoint.
func (m *Middleware) ServeACS(ctx *fiber.Ctx) error {
	// r.ParseForm()

	possibleRequestIDs := []string{}
	if m.ServiceProvider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests, err := m.RequestTracker.GetTrackedRequests(ctx)
	if err != nil {
		m.OnError(ctx, err)
		return nil
	}
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := m.ServiceProvider.ParseResponse(ctx, possibleRequestIDs)
	if err != nil {
		m.OnError(ctx, err)
		return nil
	}

	m.CreateSessionFromAssertion(ctx, assertion, m.ServiceProvider.DefaultRedirectURI)
	return nil
}

// RequireAccount is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middleware redirects the user
// to start the SAML auth flow.
// func (m *Middleware) RequireAccount(handler http.Handler) http.Handler {
// 	return http.HandlerFunc(func(ctx *fiber.Ctx) error {
// 		session, err := m.Session.GetSession(ctx)
// 		if session != nil {
// 			r = r.WithContext(ContextWithSession(r.Context(), session))
// 			handler.ServeHTTP(ctx)
// 			return
// 		}
// 		if err == ErrNoSession {
// 			m.HandleStartAuthFlow(ctx)
// 			return
// 		}

//			m.OnError(ctx, err)
//			return
//		})
//	}
func RequireAccount(handler fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		if session := SessionFromContext(ctx.Context()); session == nil {
			// http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return ctx.Status(http.StatusUnauthorized).SendString(http.StatusText(http.StatusUnauthorized))
		}
		return handler(ctx)
	}
}

// HandleStartAuthFlow is called to start the SAML authentication process.
func (m *Middleware) HandleStartAuthFlow(ctx *fiber.Ctx) error {
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	// if r.URL.Path == m.ServiceProvider.AcsURL.Path {
	if ctx.Path() == m.ServiceProvider.AcsURL.Path {
		panic("don't wrap Middleware with RequireAccount")
	}

	var binding, bindingLocation string
	if m.Binding != "" {
		binding = m.Binding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}

	authReq, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation, binding, m.ResponseBinding)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		return ctx.Status(http.StatusInternalServerError).SendString(err.Error())
	}

	// relayState is limited to 80 bytes but also must be integrity protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a signed cookie that encodes the original URL which we'll check
	// against the SAML response when we get it.
	relayState, err := m.RequestTracker.TrackRequest(ctx, authReq.ID)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		return ctx.Status(http.StatusInternalServerError).SendString(err.Error())
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, &m.ServiceProvider)
		if err != nil {
			// http.Error(w, err.Error(), http.StatusInternalServerError)
			return ctx.Status(http.StatusInternalServerError).SendString(err.Error())
		}
		// w.Header().Add("Location", redirectURL.String())
		ctx.Set("Location", redirectURL.String())
		// w.WriteHeader(http.StatusFound)
		return ctx.Status(http.StatusFound).SendString(redirectURL.String())
		// return nil
	}
	if binding == saml.HTTPPostBinding {
		// w.Header().Add("Content-Security-Policy", ""+
		// 	"default-src; "+
		// 	"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
		// 	"reflected-xss block; referrer no-referrer;")
		ctx.Set("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		// w.Header().Add("Content-type", "text/html")
		ctx.Set("Content-type", "text/html")
		// w.Write([]byte(`<!DOCTYPE html><html><body>`))
		ctx.Write([]byte(`<!DOCTYPE html><html><body>`))
		// w.Write(authReq.Post(relayState))
		ctx.Write(authReq.Post(relayState))
		// w.Write([]byte(`</body></html>`))
		ctx.Write([]byte(`</body></html>`))
		return nil
	}
	panic("not reached")
}

// CreateSessionFromAssertion is invoked by ServeHTTP when we have a new, valid SAML assertion.
func (m *Middleware) CreateSessionFromAssertion(ctx *fiber.Ctx, assertion *saml.Assertion, redirectURI string) {
	if trackedRequestIndex := ctx.FormValue("RelayState"); trackedRequestIndex != "" {
		trackedRequest, err := m.RequestTracker.GetTrackedRequest(ctx, trackedRequestIndex)
		if err != nil {
			if err == http.ErrNoCookie && m.ServiceProvider.AllowIDPInitiated {
				if uri := ctx.FormValue("RelayState"); uri != "" {
					redirectURI = uri
				}
			} else {
				m.OnError(ctx, err)
				return
			}
		} else {
			m.RequestTracker.StopTrackingRequest(ctx, trackedRequestIndex)

			redirectURI = trackedRequest.URI
		}
	}

	if err := m.Session.CreateSession(ctx, assertion); err != nil {
		m.OnError(ctx, err)
		return
	}

	// http.Redirect(ctx, redirectURI, http.StatusFound)
	ctx.Redirect(redirectURI, http.StatusFound)
}

// RequireAttribute returns a middleware function that requires that the
// SAML attribute `name` be set to `value`. This can be used to require
// that a remote user be a member of a group. It relies on the Claims assigned
// to to the context in RequireAccount.
//
// For example:
//
//	goji.Use(m.RequireAccount)
//	goji.Use(RequireAttributeMiddleware("eduPersonAffiliation", "Staff"))
// func RequireAttribute(name, value string) func(http.Handler) http.Handler {
// 	return func(handler http.Handler) http.Handler {
// 		return http.HandlerFunc(func(ctx *fiber.Ctx) error {
// 			if session := SessionFromContext(r.Context()); session != nil {
// 				// this will panic if we have the wrong type of Session, and that is OK.
// 				sessionWithAttributes := session.(SessionWithAttributes)
// 				attributes := sessionWithAttributes.GetAttributes()
// 				if values, ok := attributes[name]; ok {
// 					for _, v := range values {
// 						if v == value {
// 							handler.ServeHTTP(ctx)
// 							return
// 						}
// 					}
// 				}
// 			}
// 			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
// 		})
// 	}
// }

func RequireAttribute(name, value string) func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		if session := SessionFromContext(ctx.Context()); session != nil {
			// this will panic if we have the wrong type of Session, and that is OK.
			sessionWithAttributes := session.(SessionWithAttributes)
			attributes := sessionWithAttributes.GetAttributes()
			if values, ok := attributes[name]; ok {
				for _, v := range values {
					if v == value {
						return ctx.Next()
					}
				}
			}
		}
		return ctx.Status(http.StatusForbidden).SendString(http.StatusText(http.StatusForbidden))
	}
}
