package event

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// NewULID generates a new ULID (Universally Unique Lexicographically Sortable Identifier).
// ULIDs are time-ordered, sortable, and provide better database indexing performance than UUIDs.
//
// Format: 26 characters (base32 encoded)
// - First 10 chars: timestamp (millisecond precision)
// - Last 16 chars: randomness
//
// Benefits over UUID:
// - Time-ordered (sortable by creation time)
// - Better B-tree index performance
// - Shorter string representation
// - Monotonic within same millisecond
func NewULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// NewEventID is an alias for NewULID for backward compatibility.
func NewEventID() string {
	return NewULID()
}

// ParseULID parses a ULID string and returns the timestamp.
func ParseULID(s string) (time.Time, error) {
	id, err := ulid.Parse(s)
	if err != nil {
		return time.Time{}, err
	}
	return ulid.Time(id.Time()), nil
}

// IsULID returns true if the string is a valid ULID.
func IsULID(s string) bool {
	_, err := ulid.Parse(s)
	return err == nil
}
