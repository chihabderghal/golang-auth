package config

import (
	"github.com/chihabderghal/user-service/pkg/models"
)

func AutoMigrations() {
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.VerificationToken{})
}
