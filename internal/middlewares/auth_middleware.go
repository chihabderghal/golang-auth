package middlewares

import (
	"errors"
	"github.com/chihabderghal/golang-auth/config"
	"github.com/chihabderghal/golang-auth/pkg/models"
	"github.com/chihabderghal/golang-auth/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"os"
)

// Protected is a middleware function that protects routes by ensuring
// the user is authenticated. It checks for a JWT token in the cookies,
// parses the token to validate the user's claims, and sets the user ID
// and email in the context for further processing.
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies("accessToken")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		c.Locals("userId", claims["sub"])
		c.Locals("email", claims["email"])

		return c.Next()
	}
}

// RequireAdmin is a middleware function that checks if the current user is an admin.
// It retrieves the access token from cookies, validates the token, and checks the user's role.
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies("accessToken")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		var user models.User
		err = config.DB.Where("email = ?", claims["email"]).First(&user).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"message": "authentication failed: invalid email or password",
				})
			}
			return nil
		}

		if !user.IsAdmin {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized",
			})
		}

		return c.Next()
	}
}
