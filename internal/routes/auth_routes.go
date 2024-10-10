package routes

import (
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/gofiber/fiber/v2"
)

func AuthRouter(c *fiber.App) {

	authGroup := c.Group("/api/auth")

	authGroup.Post("/register", controllers.Register)
	authGroup.Post("/login", controllers.Login)
	authGroup.Get("/request-email-verification", controllers.SendEmailVerification)
	authGroup.Get("/verify", controllers.VerifyEmail)
	authGroup.Post("/forget-password", controllers.ForgotPassword)
	authGroup.Post("/reset-password", controllers.ResetPassword)
}
