package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"

	samlsp "github.com/meftunca/fiber-saml/samlsp"
)

var samlMiddleware *samlsp.Middleware

func hello(ctx *fiber.Ctx) error {
	// fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
	return ctx.SendString(fmt.Sprintf("Hello, %s!", samlsp.AttributeFromContext(ctx.Context(), "displayName")))
}

func logout(ctx *fiber.Ctx) error {
	// nameID := samlsp.AttributeFromContext(r.Context(), "urn:oasis:names:tc:SAML:attribute:subject-id")
	nameID := samlsp.AttributeFromContext(ctx.Context(), "urn:oasis:names:tc:SAML:attribute:subject-id")
	url, err := samlMiddleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "")
	if err != nil {
		panic(err) // TODO handle error
	}

	err = samlMiddleware.Session.DeleteSession(ctx)
	if err != nil {
		panic(err) // TODO handle error
	}

	// w.Header().Add("Location", url.String())
	ctx.Set("Location", url.String())
	// w.WriteHeader(http.StatusFound)
	return ctx.Status(http.StatusFound).SendString(http.StatusText(http.StatusFound))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlMiddleware, _ = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true, // some IdP require the SLO request to be signed
	})
	router := fiber.New()
	router.Get("/hello", samlMiddleware.RequireAccount(hello))
	router.All("/saml/", samlMiddleware.HandleStartAuthFlow)
	router.All("/logout", logout)
	log.Fatal(http.ListenAndServe(":8000", nil))
}
