package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type VerificationToken struct {
	gorm.Model
	Token     uuid.UUID `gorm:"unique"`
	ExpiredAt time.Time `gorm:"not null"`
	UserId    uint      `gorm:"not null;unique"`
}
