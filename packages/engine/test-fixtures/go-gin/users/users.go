package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type Store interface {
	Load(doc string) map[string]interface{}
}

type yamlStore struct{}

func (s yamlStore) Load(doc string) map[string]interface{} {
	var out map[string]interface{}
	yaml.Unmarshal([]byte(doc), &out)
	return out
}

var store Store = yamlStore{}

func Register(g *gin.RouterGroup) {
	g.GET("/:id", Show)
}

func Show(c *gin.Context) {
	doc := c.Query("doc")
	c.JSON(http.StatusOK, store.Load(doc))
}
