package correlation

import (
	"sort"

	"github.com/correlic/correlic-backend/internal/event"
)

func OrderEvents(events []event.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}
