package main

import (
	"net/http"

	"example.com/nethttp/auth"
	"example.com/nethttp/handlers"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /config", handlers.Config)
	mux.Handle("/admin/import", auth.Required(http.HandlerFunc(handlers.Import)))
	mux.Handle("/admin/export", auth.Gate(http.HandlerFunc(handlers.Export)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	http.Handle("/metrics", http.NotFoundHandler())
	http.ListenAndServe("127.0.0.1:8080", mux)
}
