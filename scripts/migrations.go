package scripts

import (
	"github.com/chihabderghal/golang-auth/config"
	"github.com/chihabderghal/golang-auth/pkg/models"
)

func AutoMigrations() {
	config.DB.AutoMigrate(&models.User{})
	config.DB.AutoMigrate(&models.VerificationToken{})
}
