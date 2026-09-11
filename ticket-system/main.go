package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"ticket-system/internal/handlers"
	"ticket-system/internal/middleware"
	"ticket-system/internal/store"
)

func main() {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		// A default is provided so the service is easy to run locally out of
		// the box, per the assignment's local-run contract. In any real
		// deployment, JWT_SECRET must be set to a long random value.
		jwtSecret = "dev-only-insecure-secret-change-me"
		log.Println("WARNING: JWT_SECRET not set, using an insecure default. Set JWT_SECRET in production.")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // contract requires the service to run on 8080
	}

	dataStore := store.New()
	authHandler := &handlers.AuthHandler{Store: dataStore, JWTSecret: []byte(jwtSecret)}
	ticketHandler := &handlers.TicketHandler{Store: dataStore}
	requireAuth := middleware.RequireAuth([]byte(jwtSecret))

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", healthHandler)

	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)

	// Protected routes: each is individually wrapped with the auth
	// middleware. Go 1.22's ServeMux supports method+path patterns and
	// {id} wildcards natively, so no external router is needed.
	mux.Handle("POST /tickets", requireAuth(http.HandlerFunc(ticketHandler.Create)))
	mux.Handle("GET /tickets", requireAuth(http.HandlerFunc(ticketHandler.List)))
	mux.Handle("GET /tickets/{id}", requireAuth(http.HandlerFunc(ticketHandler.Get)))
	mux.Handle("PATCH /tickets/{id}/status", requireAuth(http.HandlerFunc(ticketHandler.UpdateStatus)))

	addr := ":" + port
	log.Printf("ticket-system listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
