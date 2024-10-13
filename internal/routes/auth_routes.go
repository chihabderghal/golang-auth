package routes

import (
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/chihabderghal/user-service/internal/middlewares"
	"github.com/gofiber/fiber/v2"
)

func AuthRouter(c *fiber.App) {

	auth := c.Group("/api/auth")

	auth.Post("/register", controllers.Register)
	auth.Post("/login", controllers.Login)
	auth.Get("/request-email-verification", middlewares.Protected(), controllers.SendEmailVerification)
	auth.Get("/verify", middlewares.Protected(), controllers.VerifyEmail)
	auth.Post("/forget-password", middlewares.Protected(), controllers.ForgotPassword)
	auth.Post("/reset-password", middlewares.Protected(), controllers.ResetPassword)
}
