package handlers

import (
	"io"
	"net/http"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"
)

type settings struct {
	Name string
}

func Config(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	parse(body)
	w.WriteHeader(http.StatusNoContent)
}

func parse(b []byte) {
	var cfg map[string]interface{}
	yaml.Unmarshal(b, &cfg)
}

func Import(w http.ResponseWriter, r *http.Request) {
	var s settings
	doc := r.FormValue("doc")
	toml.Decode(doc, &s)
}

func Export(w http.ResponseWriter, r *http.Request) {
	out, _ := yaml.Marshal(settings{Name: "x"})
	w.Write(out)
}

// Dead is never reached from a route.
func Dead() {
	var cfg map[string]interface{}
	yaml.Unmarshal([]byte("a: 1"), &cfg)
}
