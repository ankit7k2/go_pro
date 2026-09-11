package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"ticket-system/internal/middleware"
	"ticket-system/internal/models"
	"ticket-system/internal/store"
)

type TicketHandler struct {
	Store *store.Store
}

type createTicketRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Create handles POST /tickets.
func (h *TicketHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}

	ticket := h.Store.CreateTicket(userID, req.Title, req.Description)
	writeJSON(w, http.StatusCreated, ticket)
}

// List handles GET /tickets — returns only tickets owned by the caller.
func (h *TicketHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tickets := h.Store.ListTicketsByUser(userID)
	writeJSON(w, http.StatusOK, tickets)
}

// Get handles GET /tickets/{id} — 404s if the ticket doesn't exist OR isn't
// owned by the caller, so ownership can't be probed via 403-vs-404 timing.
func (h *TicketHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	ticketID := r.PathValue("id")
	ticket, err := h.Store.GetOwnedTicket(ticketID, userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	writeJSON(w, http.StatusOK, ticket)
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

// UpdateStatus handles PATCH /tickets/{id}/status.
func (h *TicketHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	ticketID := r.PathValue("id")

	// Ownership check happens before we even look at the request body:
	// an attacker shouldn't learn anything about a ticket they don't own.
	existing, err := h.Store.GetOwnedTicket(ticketID, userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	newStatus := models.TicketStatus(strings.TrimSpace(req.Status))
	if !newStatus.IsValid() {
		writeError(w, http.StatusBadRequest, "status must be one of: open, in_progress, closed")
		return
	}

	if !models.CanTransition(existing.Status, newStatus) {
		writeError(w, http.StatusConflict,
			"invalid status transition from '"+string(existing.Status)+"' to '"+string(newStatus)+"'")
		return
	}

	updated, err := h.Store.UpdateTicketStatus(ticketID, newStatus)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update ticket")
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
