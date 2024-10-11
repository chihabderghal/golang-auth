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

func main() {
	app := fiber.New()
	port := os.Getenv("PORT")

	// Setup routes
	routes.AuthRouter(app)
	routes.GoogleRouter(app)

	log.Fatal(app.Listen(":" + port))
}
