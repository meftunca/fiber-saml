package samlidp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"

	"github.com/zenazn/goji/web"
	"golang.org/x/crypto/bcrypt"
)

// User represents a stored user. The data here are used to
// populate user once the user has authenticated.
type User struct {
	Name              string   `json:"name"`
	PlaintextPassword *string  `json:"password,omitempty"` // not stored
	HashedPassword    []byte   `json:"hashed_password,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	ScopedAffiliation string   `json:"scoped_affiliation,omitempty"`
}

// HandleListUsers handles the `GET /users/` request and responds with a JSON formatted list
// of user names.
func (s *Server) HandleListUsers(c web.C, ctx *fiber.Ctx) error {
	users, err := s.Store.List("/users/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}

	// json.NewEncoder(w).Encode(struct {
	// 	Users []string `json:"users"`
	// }{Users: users})
	return ctx.JSON(
		fiber.Map{
			"users": users,
		},
	)
}

// HandleGetUser handles the `GET /users/:id` request and responds with the user object in JSON
// format. The HashedPassword field is excluded.
func (s *Server) HandleGetUser(c web.C, ctx *fiber.Ctx) error {
	user := User{}
	err := s.Store.Get(fmt.Sprintf("/users/%s", c.URLParams["id"]), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}
	user.HashedPassword = nil
	// json.NewEncoder(w).Encode(user)
	return ctx.JSON(user)
}

// HandlePutUser handles the `PUT /users/:id` request. It accepts a JSON formatted user object in
// the request body and stores it. If the PlaintextPassword field is present then it is hashed
// and stored in HashedPassword. If the PlaintextPassword field is not present then
// HashedPassword retains it's stored value.
func (s *Server) HandlePutUser(c web.C, ctx *fiber.Ctx) error {
	user := User{}
	// if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
	if err := json.Unmarshal(ctx.Body(), &user); err != nil {
		s.logger.Printf("ERROR: %s", err)
		return ctx.Status(http.StatusBadRequest).SendString(http.StatusText(http.StatusBadRequest))

	}
	user.Name = c.URLParams["id"]

	if user.PlaintextPassword != nil {
		var err error
		user.HashedPassword, err = bcrypt.GenerateFromPassword([]byte(*user.PlaintextPassword), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("ERROR: %s", err)
			// http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))
		}
	} else {
		existingUser := User{}
		err := s.Store.Get(fmt.Sprintf("/users/%s", c.URLParams["id"]), &existingUser)
		switch {
		case err == nil:
			user.HashedPassword = existingUser.HashedPassword
		case err == ErrNotFound:
			// nop
		default:
			s.logger.Printf("ERROR: %s", err)
			// http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))
		}
	}
	user.PlaintextPassword = nil

	err := s.Store.Put(fmt.Sprintf("/users/%s", c.URLParams["id"]), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}
	return ctx.Status(http.StatusNoContent).SendString(http.StatusText(http.StatusNoContent))

}

// HandleDeleteUser handles the `DELETE /users/:id` request.
func (s *Server) HandleDeleteUser(c web.C, ctx *fiber.Ctx) error {
	err := s.Store.Delete(fmt.Sprintf("/users/%s", c.URLParams["id"]))
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		return ctx.Status(http.StatusInternalServerError).SendString(http.StatusText(http.StatusInternalServerError))

	}
	return ctx.Status(http.StatusNoContent).SendString(http.StatusText(http.StatusNoContent))

}
