package storage

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

type Filter struct {
	Types   []string
	Sources []string
}

type EventStore interface {
	Append(ctx context.Context, e event.Event) error

	GetRange(
		ctx context.Context,
		hostID string,
		from time.Time,
		to time.Time,
		filter *Filter,
	) ([]event.Event, error)
}
