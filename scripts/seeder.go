package scripts

import (
	"github.com/chihabderghal/golang-auth/config"
	"github.com/chihabderghal/golang-auth/pkg/models"
	"github.com/chihabderghal/golang-auth/pkg/utils"
	"github.com/go-faker/faker/v4"
)

// SeedRootUser seeds a root admin user into the database.
// This user has verified status and admin privileges.
func SeedRootUser() error {

	hash, _ := utils.HashString("password123")
	root := models.User{
		FirstName:  "Chihab",
		LastName:   "Derghal",
		Email:      "chihab@gmail.com",
		Password:   hash,
		IsVerified: true,
		IsAdmin:    true,
	}

	if err := config.DB.Create(&root).Error; err != nil {
		return err
	}

	return nil
}

// SeedFakeUsers seeds a specified number of fake users into the database.
// Users have randomly generated first names, last names, emails, and passwords.
func SeedFakeUsers(numUsers int) error {
	for i := 0; i < numUsers; i++ {

		hash, _ := utils.HashString(faker.Password())
		user := models.User{
			FirstName: faker.FirstName(),
			LastName:  faker.LastName(),
			Email:     faker.Email(),
			Password:  hash,
		}

		if err := config.DB.Create(&user).Error; err != nil {
			return err
		}
	}

	return nil
}

// SeedAdminUsers seeds a specified number of admin users into the database.
// Admin users have randomly generated names and emails, with default admin settings.
func SeedAdminUsers(numUsers int) error {
	for i := 0; i < numUsers; i++ {

		hash, _ := utils.HashString("password123")
		user := models.User{
			FirstName:  faker.FirstName(),
			LastName:   faker.LastName(),
			Email:      faker.Email(),
			IsAdmin:    true,
			IsVerified: true,
			Password:   hash,
		}

		if err := config.DB.Create(&user).Error; err != nil {
			return err
		}
	}

	return nil
}
