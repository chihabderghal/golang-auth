package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Picture           string            `gorm:"size:255;default:nil"`
	FirstName         string            `gorm:"size:255"`
	LastName          string            `gorm:"size:255"`
	Email             string            `gorm:"type:varchar(100);unique"`
	IsVerified        bool              `gorm:"default:false"`
	Password          string            `gorm:"size:255;default:nil"`
	VerificationToken VerificationToken `gorm:"foreignKey:UserId;constraint:OnDelete:CASCADE"`
}
