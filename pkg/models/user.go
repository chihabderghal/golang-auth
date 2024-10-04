package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	FirstName  string `gorm:"size:255"`
	LastName   string `gorm:"size:255"`
	Country    string `gorm:"size:255"`
	Email      string `gorm:"type:varchar(100);unique"`
	IsVerified bool   `gorm:"default:false"`
	Password   string `gorm:"size:255"`
}
