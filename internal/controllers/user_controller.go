package controllers

import (
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"os"
)

// GetAllUsers retrieves all users from the database.
// It returns a list of users in the response with a status of 200 (OK).
// If there is a database error, it responds with a 500 (Internal Server Error) and an error message.
func GetAllUsers(c *fiber.Ctx) error {
	// Fetch all users from the database
	var users []models.User
	if err := config.DB.Find(&users).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	// Respond with the list of users
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": users,
	})
}

// GetUserById retrieves the user based on the ID in the JWT token claims.
// It checks if the user is authenticated and returns the user's data.
// If unauthorized or if the user is not found, it returns an appropriate error response.
func GetUserById(c *fiber.Ctx) error {
	// Retrieve the access token from cookies
	token := c.Cookies("accessToken")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse the JWT token to get user claims
	claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	// Fetch the user from the database using the ID from the token claims
	var user models.User
	err = config.DB.Where("id = ?", claims["sub"]).First(&user).Error
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "authentication failed: invalid email or password",
		})
	}

	// Respond with the user data
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"user": user,
	})
}

// GetAllAdminUsers retrieves all admin users from the database.
// It returns a list of users who have admin privileges in the response.
// If there is a database error, it responds with a 500 (Internal Server Error).
func GetAllAdminUsers(c *fiber.Ctx) error {
	// Fetch all admin users from the database
	var users []models.User
	if err := config.DB.Where("is_admin = true").Find(&users).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	// Respond with the list of admin users
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": users,
	})
}

// DeleteUserById deletes the user based on the ID in the JWT token claims.
// It ensures the user is authenticated and deletes the user from the database.
// If unauthorized or an error occurs during deletion, an appropriate error response is returned.
func DeleteUserById(c *fiber.Ctx) error {
	// Retrieve the access token from cookies
	token := c.Cookies("accessToken")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse the JWT token to get user claims
	claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	// Fetch the user from the database using the ID from the token claims
	var user models.User
	err = config.DB.Where("id = ?", claims["sub"]).First(&user).Error
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong",
		})
	}

	// Delete the user from the database
	if err := config.DB.Delete(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to delete user, try again later",
		})
	}

	// Return success response after deletion
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User deleted successfully",
	})
}
