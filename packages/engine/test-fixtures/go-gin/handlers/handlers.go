package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type renderRequest struct {
	Doc string `json:"doc"`
}

func Render(c *gin.Context) {
	var req renderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var out map[string]interface{}
	yaml.Unmarshal([]byte(req.Doc), &out)
	c.JSON(http.StatusOK, out)
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	parse(id)
	c.Status(http.StatusNoContent)
}

func Me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": 1})
}

func parse(doc string) {
	var out map[string]interface{}
	yaml.Unmarshal([]byte(doc), &out)
}

// Unused is never reached from a route.
func Unused() {
	parse("a: 1")
}
