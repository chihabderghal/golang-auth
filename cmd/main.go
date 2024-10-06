package main

import (
	"github.com/chihabderghal/user-service/internal/config"
	"github.com/chihabderghal/user-service/internal/routes"
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

	// Setup routes
	routes.GlobalRouter(app)
	routes.GlobalRouter(app)

	log.Fatal(app.Listen(":" + port))
}
