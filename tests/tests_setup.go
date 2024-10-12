package tests_setup

import (
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/internal/routes"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/gofiber/fiber/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func CreateTestDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to connect to test database")
	}

	// Run migrations (creates the users table)
	config.DB = db
	db.AutoMigrate(&models.User{})

	return db, nil
}

func Setup() *fiber.App {
	app := fiber.New()

	// Setup routes
	routes.AuthRouter(app)

	return app
}
