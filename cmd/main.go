package main

import (
	"github.com/chihabderghal/golang-auth/config"
	"github.com/chihabderghal/golang-auth/internal/routes"
	"github.com/chihabderghal/golang-auth/scripts"
	"github.com/gofiber/fiber/v2"
	"log"
	"os"
)

func init() {
	config.LoadEnv()
	config.DBConnector()
	scripts.AutoMigrations()

	err := scripts.SeedRootUser()
	if err != nil {
		return
	}

	err = scripts.SeedFakeUsers(20)
	if err != nil {
		return
	}

	err = scripts.SeedAdminUsers(5)
	if err != nil {
		return
	}

}

func Setup() *fiber.App {
	app := fiber.New()

	// Setup routes
	routes.AuthRouter(app)
	routes.GoogleRouter(app)
	routes.UserRouter(app)

	return app
}

func main() {
	app := Setup()
	port := os.Getenv("PORT")

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Hello World",
		})
	})

	log.Fatal(app.Listen(":" + port))
}
