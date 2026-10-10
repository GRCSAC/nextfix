package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v2"
)

func Routes() chi.Router {
	r := chi.NewRouter()
	r.With(requireKey).Get("/items", items)
	r.Get("/public", public)
	return r
}

func requireKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func items(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("filter")
	var f map[string]interface{}
	yaml.Unmarshal([]byte(q), &f)
}

func public(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("public"))
}
