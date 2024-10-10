package routes

import (
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/gofiber/fiber/v2"
)

func GlobalRouter(c *fiber.App) {

	c.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Everything looks good",
		})
	})

	c.Post("/api/auth/register", controllers.Register)
	c.Post("/api/auth/login", controllers.Login)
	c.Get("/api/auth/request-email-verification", controllers.SendEmailVerification)
	c.Get("/api/auth/verify", controllers.VerifyEmail)
	c.Post("/api/auth/forget-password", controllers.ForgotPassword)
	c.Post("/api/auth/reset-password", controllers.ResetPassword)
}
