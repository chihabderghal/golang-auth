package scripts

import (
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/pkg/models"
)

func AutoMigrations() {
	config.DB.AutoMigrate(&models.User{})
	config.DB.AutoMigrate(&models.VerificationToken{})
}
