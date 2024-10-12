package routes

import (
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/gofiber/fiber/v2"
)

func AuthRouter(c *fiber.App) {

	auth := c.Group("/api/auth")

	auth.Post("/register", controllers.Register)
	auth.Post("/login", controllers.Login)
	auth.Get("/request-email-verification", controllers.SendEmailVerification)
	auth.Get("/verify", controllers.VerifyEmail)
	auth.Post("/forget-password", controllers.ForgotPassword)
	auth.Post("/reset-password", controllers.ResetPassword)
}
