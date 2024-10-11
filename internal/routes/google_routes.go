package routes

import (
	"context"
	"encoding/json"
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/internal/auth"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"os"
	"time"
)

type GoogleUser struct {
	Email         string `json:"email"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Id            string `json:"id"`
	Locale        string `json:"locale"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

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

		//set client for getting googleUser info like email, name, etc.
		client := oauthConf.Client(context.Background(), token)

		//get googleUser info
		response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to get googleUser info: " + err.Error())
		}

		defer response.Body.Close()

		// googleUser variable
		var googleUser GoogleUser

		//reading response body from client
		bytes, err := io.ReadAll(response.Body)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error reading response body: " + err.Error())
		}

		// unmarshal googleUser info
		err = json.Unmarshal(bytes, &googleUser)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error unmarshal json body " + err.Error())
		}

		myUser := models.User{
			Picture:    googleUser.Picture,
			FirstName:  googleUser.FamilyName,
			LastName:   googleUser.GivenName,
			Email:      googleUser.Email,
			IsVerified: true,
		}

		// Return Tokens if the googleUser exists
		if err := config.DB.Where("email = ?", googleUser.Email).First(&myUser).Error; err == nil {
			tokens := auth.Tokens{
				AccessToken:  utils.GenerateAccessToken(myUser),
				RefreshToken: utils.GenerateRefreshToken(myUser),
			}

			return c.Status(fiber.StatusOK).JSON(tokens)
		}

		// Save googleUser in DB
		creation := config.DB.Create(&myUser)
		if creation.Error != nil {
			c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "failed to create googleUser",
			})
		}

		// Generate Access and Refresh Tokens
		tokens := auth.Tokens{
			AccessToken:  utils.GenerateAccessToken(myUser),
			RefreshToken: utils.GenerateRefreshToken(myUser),
		}

		// Set Access Token in the Cookie
		c.Cookie(&fiber.Cookie{
			Name:     "accessToken",
			Value:    tokens.AccessToken,
			Expires:  time.Now().Add(time.Minute * 15),
			HTTPOnly: true,
			Secure:   false,
		})

		// Set Refresh Token in the Cookie
		c.Cookie(&fiber.Cookie{
			Name:     "refreshToken",
			Value:    tokens.RefreshToken,
			Expires:  time.Now().Add(time.Hour * 24 * 7 * 4),
			HTTPOnly: true,
			Secure:   false,
		})

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "Login Successfully",
		})
	})
}
