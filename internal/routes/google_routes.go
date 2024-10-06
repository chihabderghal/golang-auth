package routes

import (
	"context"
	"encoding/json"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"os"
)

func GoogleRouter(app *fiber.App) {
	oauthConf := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	app.Get("/api/auth/google/login", func(c *fiber.Ctx) error {
		url := oauthConf.AuthCodeURL("state")
		return c.Redirect(url)
	})

	app.Get("/oauth/redirect", func(c *fiber.Ctx) error {
		//get code from query params for generating token
		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange token")
		}

		//get token
		token, err := oauthConf.Exchange(context.Background(), code)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange token: " + err.Error())
		}

		//set client for getting user info like email, name, etc.
		client := oauthConf.Client(context.Background(), token)
		//get user info
		response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to get user info: " + err.Error())
		}

		defer response.Body.Close()

		//user variable
		var user models.GoogleUser

		//reading response body from client
		bytes, err := io.ReadAll(response.Body)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error reading response body: " + err.Error())
		}

		//unmarshal user info
		err = json.Unmarshal(bytes, &user)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error unmarshal json body " + err.Error())
		}

		// TODO: Save user in DB

		return c.Status(fiber.StatusOK).JSON(user) //return user info
	})
}
