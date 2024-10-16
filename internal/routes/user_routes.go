package routes

import (
	"github.com/chihabderghal/golang-auth/internal/controllers"
	"github.com/chihabderghal/golang-auth/internal/middlewares"
	"github.com/gofiber/fiber/v2"
)

func UserRouter(app *fiber.App) {
	users := app.Group("/api/users")

	users.Get("/get-all",
		middlewares.Protected(),
		middlewares.RequireAdmin(),
		controllers.GetAllUsers,
	)

	users.Get("/profile",
		middlewares.Protected(),
		controllers.GetUserById,
	)

	users.Get("/get-admin-users",
		middlewares.Protected(),
		middlewares.RequireAdmin(),
		controllers.GetAllAdminUsers,
	)

	users.Delete("/delete-user",
		middlewares.Protected(),
		controllers.DeleteUserById,
	)

	users.Put("/update-user",
		middlewares.Protected(),
		controllers.UpdateUser,
	)
}
