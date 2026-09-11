// Package middleware contains HTTP middleware, currently just JWT auth.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"ticket-system/internal/auth"
)

// contextKey is an unexported type to avoid collisions in context.Context.
type contextKey string

const userIDContextKey contextKey = "userID"

// RequireAuth wraps a handler so it only runs if the request carries a
// valid "Authorization: Bearer <token>" header. On success, the
// authenticated user's ID is placed in the request context.
func RequireAuth(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if header == "" || !strings.HasPrefix(header, prefix) {
				writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}

			tokenString := strings.TrimPrefix(header, prefix)
			userID, err := auth.ParseToken(tokenString, secret)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext extracts the authenticated user's ID set by RequireAuth.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDContextKey).(string)
	return id, ok
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
