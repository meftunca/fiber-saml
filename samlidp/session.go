package samlidp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	saml "github.com/meftunca/fiber-saml"

	"golang.org/x/crypto/bcrypt"

	"github.com/zenazn/goji/web"
)

var sessionMaxAge = time.Hour

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (s *Server) GetSession(ctx *fiber.Ctx, req *saml.IdpAuthnRequest) *saml.Session {
	// if we received login credentials then maybe we can create a session
	if ctx.Method() == "POST" && ctx.FormValue("user") != "" {
		user := User{}
		if err := s.Store.Get(fmt.Sprintf("/users/%s", ctx.FormValue("user")), &user); err != nil {
			s.sendLoginForm(ctx, req, "Invalid username or password")
			return nil
		}

		if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(ctx.FormValue("password"))); err != nil {
			s.sendLoginForm(ctx, req, "Invalid username or password")
			return nil
		}

		session := &saml.Session{
			ID:                    base64.StdEncoding.EncodeToString(randomBytes(32)),
			NameID:                user.Email,
			CreateTime:            saml.TimeNow(),
			ExpireTime:            saml.TimeNow().Add(sessionMaxAge),
			Index:                 hex.EncodeToString(randomBytes(32)),
			UserName:              user.Name,
			Groups:                user.Groups[:],
			UserEmail:             user.Email,
			UserCommonName:        user.CommonName,
			UserSurname:           user.Surname,
			UserGivenName:         user.GivenName,
			UserScopedAffiliation: user.ScopedAffiliation,
		}
		if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &session); err != nil {
			// http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))
			return nil
		}

		ctx.Cookie(&fiber.Cookie{
			Name:     "session",
			Value:    session.ID,
			MaxAge:   int(sessionMaxAge.Seconds()),
			HTTPOnly: true,
			Secure:   ctx.Secure(),
			Path:     "/",
		})

		return session
	}

	// if sessionCookie, err := r.Cookie("session"); err == nil {
	if sessionCookie := ctx.Cookies("session"); sessionCookie != "" {
		session := &saml.Session{}
		// if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), session); err != nil {
		if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie), session); err != nil {
			if err == ErrNotFound {
				s.sendLoginForm(ctx, req, "")
				return nil
			}
			ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))
			return nil
		}

		if saml.TimeNow().After(session.ExpireTime) {
			s.sendLoginForm(ctx, req, "")
			return nil
		}
		return session
	}

	s.sendLoginForm(ctx, req, "")
	return nil
}

// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (s *Server) sendLoginForm(ctx *fiber.Ctx, req *saml.IdpAuthnRequest, toast string) {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<html>` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="text" name="user" placeholder="user" value="" />` +
		`<input type="password" name="password" placeholder="password" value="" />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Log In" />` +
		`</form>` +
		`</html>`))
	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         req.IDP.SSOURL.String(),
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
	}

	// if err := tmpl.Execute(w, data); err != nil {
	if err := tmpl.Execute(ctx, data); err != nil {
		panic(err)
	}
}

// HandleLogin handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HandleLogin(c web.C, ctx *fiber.Ctx) error {
	// if err := r.ParseForm(); err != nil {
	if string(ctx.Body()) == "" {
		return ctx.Status(http.StatusBadRequest).SendString(http.StatusText(http.StatusBadRequest))

	}
	session := s.GetSession(ctx, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if session == nil {
		return ctx.Status(http.StatusUnauthorized).SendString(http.StatusText(http.StatusUnauthorized))
	}
	// json.NewEncoder(w).Encode(session)
	return ctx.JSON(session)
}

// HandleListSessions handles the `GET /sessions/` request and responds with a JSON formatted list
// of session names.
func (s *Server) HandleListSessions(c web.C, ctx *fiber.Ctx) error {
	sessions, err := s.Store.List("/sessions/")
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}

	// json.NewEncoder(w).Encode(struct {
	// 	Sessions []string `json:"sessions"`
	// }{Sessions: sessions})
	return ctx.JSON(struct {
		Sessions []string `json:"sessions"`
	}{Sessions: sessions})
}

// HandleGetSession handles the `GET /sessions/:id` request and responds with the session
// object in JSON format.
func (s *Server) HandleGetSession(c web.C, ctx *fiber.Ctx) error {
	session := saml.Session{}
	err := s.Store.Get(fmt.Sprintf("/sessions/%s", c.URLParams["id"]), &session)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}
	// json.NewEncoder(w).Encode(session)
	return ctx.JSON(session)
}

// HandleDeleteSession handles the `DELETE /sessions/:id` request. It invalidates the
// specified session.
func (s *Server) HandleDeleteSession(c web.C, ctx *fiber.Ctx) error {
	err := s.Store.Delete(fmt.Sprintf("/sessions/%s", c.URLParams["id"]))
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}
	return ctx.Status(http.StatusNoContent).SendString(http.StatusText(http.StatusNoContent))

}
