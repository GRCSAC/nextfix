package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func RequireLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := c.Cookie("session"); err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "login"})
			return
		}
		c.Next()
	}
}
