package main

import (
	"github.com/chihabderghal/user-service/internal/config"
	"github.com/chihabderghal/user-service/internal/controllers"
	"github.com/gofiber/fiber/v2"
	"log"
	"os"
)

func init() {
	config.LoadEnv()
	config.DBConnector()
	config.AutoMigrations()
}

func main() {
	app := fiber.New()
	port := os.Getenv("PORT")

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Everything looks good",
		})
	})

	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Post("/api/refresh", controllers.Refresh)

	log.Fatal(app.Listen(":" + port))
}
