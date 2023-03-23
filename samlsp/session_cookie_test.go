package samlsp

// import (
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"

// 	saml "github.com/meftunca/fiber-saml"
// 	"gotest.tools/assert"
// 	is "gotest.tools/assert/cmp"
// )

// func TestCookieSameSite(t *testing.T) {
// 	t.Parallel()

// 	csp := CookieSessionProvider{
// 		Name:   "token",
// 		Domain: "localhost",
// 		Codec: DefaultSessionCodec(Options{
// 			Key: NewMiddlewareTest(t).Key,
// 		}),
// 	}

// 	getSessionCookie := func(tb testing.TB) *http.Cookie {
// 		resp := httptest.NewRecorder()
// 		req := httptest.NewRequest(http.MethodGet, "/", nil)
// 		err := csp.CreateSession(resp, req, &saml.Assertion{})
// 		assert.Check(t, err)

// 		cookies := resp.Result().Cookies()
// 		assert.Check(t, is.Len(cookies, 1), "Expected to have a cookie set")

// 		return cookies[0]
// 	}

// 	t.Run("no same site", func(t *testing.T) {
// 		cookie := getSessionCookie(t)
// 		assert.Check(t, is.Equal(string(0), cookie.SameSite))
// 	})

// 	t.Run("with same site", func(t *testing.T) {
// 		csp.SameSite = stringStrictMode
// 		cookie := getSessionCookie(t)
// 		assert.Check(t, is.Equal(stringStrictMode, cookie.SameSite))
// 	})
// }
