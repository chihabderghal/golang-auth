package routes

import (
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/gofiber/fiber/v2"
)

func Router(c *fiber.App) {

	c.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Everything looks good",
		})
	})

	c.Post("/api/register", controllers.Register)
	c.Post("/api/login", controllers.Login)
	c.Post("/api/refresh", controllers.Refresh)
}
