package models

import "time"

// User represents a registered account.
// PasswordHash is never serialized to JSON (json:"-").
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

// TicketStatus is a restricted set of allowed ticket states.
type TicketStatus string

const (
	StatusOpen       TicketStatus = "open"
	StatusInProgress TicketStatus = "in_progress"
	StatusClosed     TicketStatus = "closed"
)

// IsValid reports whether s is one of the three allowed statuses.
func (s TicketStatus) IsValid() bool {
	switch s {
	case StatusOpen, StatusInProgress, StatusClosed:
		return true
	}
	return false
}

// Ticket represents a single support ticket owned by a user.
type Ticket struct {
	ID          string       `json:"id"`
	UserID      string       `json:"user_id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Status      TicketStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// allowedTransitions encodes the required status flow:
//
//	open -> in_progress -> closed
//	closed cannot move back to open or in_progress
var allowedTransitions = map[TicketStatus][]TicketStatus{
	StatusOpen:       {StatusInProgress, StatusClosed},
	StatusInProgress: {StatusClosed},
	StatusClosed:     {}, // terminal state, no transitions out
}

// CanTransition reports whether moving from `from` to `to` is legal.
// Moving to the same status is also disallowed (no-op update is not a transition).
func CanTransition(from, to TicketStatus) bool {
	for _, allowed := range allowedTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}
