// Package store provides a simple thread-safe in-memory data store.
//
// The assignment allows in-memory, SQLite, or Postgres storage. In-memory
// is used here to keep the implementation simple, as instructed. All state
// lives inside the Store struct behind a mutex, so swapping this out for a
// real database later only means changing this one file — handlers talk to
// the Store interface-shaped methods below, not to maps directly.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"ticket-system/internal/models"
)

var (
	ErrUserExists     = errors.New("user with this email already exists")
	ErrUserNotFound   = errors.New("user not found")
	ErrTicketNotFound = errors.New("ticket not found")
	ErrNotOwner       = errors.New("ticket does not belong to this user")
)

type Store struct {
	mu sync.RWMutex

	usersByID    map[string]*models.User
	usersByEmail map[string]*models.User
	tickets      map[string]*models.Ticket
}

func New() *Store {
	return &Store{
		usersByID:    make(map[string]*models.User),
		usersByEmail: make(map[string]*models.User),
		tickets:      make(map[string]*models.Ticket),
	}
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateUser adds a new user. Returns ErrUserExists if the email is taken.
func (s *Store) CreateUser(email, passwordHash string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[email]; exists {
		return nil, ErrUserExists
	}

	u := &models.User{
		ID:           newID(),
		Email:        email,
		PasswordHash: passwordHash,
	}
	s.usersByID[u.ID] = u
	s.usersByEmail[u.Email] = u
	return u, nil
}

// GetUserByEmail looks up a user by email. Returns ErrUserNotFound if absent.
func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.usersByEmail[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// CreateTicket creates a new ticket owned by userID, defaulting to status "open".
func (s *Store) CreateTicket(userID, title, description string) *models.Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	t := &models.Ticket{
		ID:          newID(),
		UserID:      userID,
		Title:       title,
		Description: description,
		Status:      models.StatusOpen,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.tickets[t.ID] = t
	return t
}

// ListTicketsByUser returns all tickets owned by userID, newest first.
func (s *Store) ListTicketsByUser(userID string) []*models.Ticket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.Ticket, 0)
	for _, t := range s.tickets {
		if t.UserID == userID {
			result = append(result, t)
		}
	}
	// Simple insertion sort by CreatedAt desc — ticket counts are small, so
	// this stays readable without pulling in sort for a one-off comparison.
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j].CreatedAt.After(result[j-1].CreatedAt); j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
	return result
}

// GetOwnedTicket returns the ticket only if it exists AND belongs to userID.
// This is the single choke point for ownership enforcement on reads.
func (s *Store) GetOwnedTicket(ticketID, userID string) (*models.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tickets[ticketID]
	if !ok {
		return nil, ErrTicketNotFound
	}
	if t.UserID != userID {
		return nil, ErrNotOwner
	}
	return t, nil
}

// UpdateTicketStatus applies a validated status transition to a ticket the
// caller already confirmed is owned by userID (via GetOwnedTicket).
func (s *Store) UpdateTicketStatus(ticketID string, newStatus models.TicketStatus) (*models.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[ticketID]
	if !ok {
		return nil, ErrTicketNotFound
	}
	t.Status = newStatus
	t.UpdatedAt = time.Now().UTC()
	return t, nil
}
