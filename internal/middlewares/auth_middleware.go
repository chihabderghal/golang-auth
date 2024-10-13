package middlewares

import (
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"os"
)

// Protected protect routes
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
