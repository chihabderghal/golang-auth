package main

import (
	config "github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/internal/routes"
	"github.com/chihabderghal/user-service/scripts"
	"github.com/gofiber/fiber/v2"
	"log"
	"os"
)

func init() {
	config.LoadEnv()
	config.DBConnector()
	scripts.AutoMigrations()
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

	log.Fatal(app.Listen(":" + port))
}
