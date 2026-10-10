package main

import (
	"github.com/gin-gonic/gin"

	"example.com/ginapp/handlers"
	"example.com/ginapp/middleware"
	"example.com/ginapp/users"
)

func main() {
	r := gin.Default()
	r.Use(gin.Logger())
	api := r.Group("/api")
	api.POST("/render", handlers.Render)
	admin := api.Group("/admin", middleware.JWTAuth())
	admin.DELETE("/users/:id", handlers.DeleteUser)
	api.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	users.Register(api.Group("/users"))
	api.Use(middleware.RequireLogin())
	api.GET("/me", handlers.Me)
	r.Run(":8080")
}
