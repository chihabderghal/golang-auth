package middlewares

import (
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"os"
)

// Protected is a middleware function that protects routes by ensuring
// the user is authenticated. It checks for a JWT token in the cookies,
// parses the token to validate the user's claims, and sets the user ID
// and email in the context for further processing.
//
// Returns:
// - fiber.Handler: A Fiber middleware handler that checks for authentication.
// If the token is missing or invalid, it responds with a 401 Unauthorized status.
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies("token")
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
