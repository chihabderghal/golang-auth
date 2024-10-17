package tests_setup

import (
	"github.com/chihabderghal/golang-auth/config"
	"github.com/chihabderghal/golang-auth/internal/routes"
	"github.com/chihabderghal/golang-auth/pkg/models"
	"github.com/chihabderghal/golang-auth/pkg/utils"
	"github.com/go-faker/faker/v4"
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

// SeedFakeUsers seeds a specified number of fake users into the database.
// Users have randomly generated first names, last names, emails, and passwords.
func SeedFakeUsers(db *gorm.DB, numUsers int) error {
	for i := 0; i < numUsers; i++ {

		hash, _ := utils.HashString(faker.Password())
		user := models.User{
			FirstName: faker.FirstName(),
			LastName:  faker.LastName(),
			Email:     faker.Email(),
			Password:  hash,
		}

		if err := db.Create(&user).Error; err != nil {
			return err
		}
	}

	return nil
}
