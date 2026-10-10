package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"gopkg.in/yaml.v2"

	"example.com/chiapp/api"
)

var tokenAuth = jwtauth.New("HS256", []byte("secret"), nil)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", home)
	r.Post("/parse", parseHandler)
	r.Route("/admin", func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator(tokenAuth))
		r.Get("/export", exportHandler)
	})
	r.Mount("/api", api.Routes())
	r.Group(func(r chi.Router) {
		r.Use(adminOnly)
		r.Delete("/users/{id}", deleteUser)
	})
	http.ListenAndServe(":3000", r)
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("home"))
}

func parseHandler(w http.ResponseWriter, r *http.Request) {
	var v map[string]string
	dec := json.NewDecoder(r.Body)
	dec.Decode(&v)
	var out map[string]interface{}
	yaml.Unmarshal([]byte(v["doc"]), &out)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("config.yml")
	var out map[string]interface{}
	yaml.Unmarshal(data, &out)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Role") != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
