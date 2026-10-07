package notification

import (
	"context"
	"log"
	"time"
)

// DeliveryWorker polls the delivery queue and dispatches to senders.
type DeliveryWorker struct {
	deliveryStore *DeliveryStore
	endpointStore *EndpointStore
	webhook       *WebhookSender
	slack         *SlackSender
	pollInterval  time.Duration
	done          chan struct{}
}

// NewDeliveryWorker creates a new delivery worker.
func NewDeliveryWorker(deliveryStore *DeliveryStore, endpointStore *EndpointStore) *DeliveryWorker {
	if deliveryStore == nil || endpointStore == nil {
		return nil
	}
	return &DeliveryWorker{
		deliveryStore: deliveryStore,
		endpointStore: endpointStore,
		webhook:       NewWebhookSender(),
		slack:         NewSlackSender(),
		pollInterval:  5 * time.Second,
		done:          make(chan struct{}),
	}
}

// Start begins the polling loop. Call in a goroutine.
func (w *DeliveryWorker) Start() {
	if w == nil {
		return
	}
	log.Println("Notification delivery worker started")
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			log.Println("Notification delivery worker stopped")
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

// Stop signals the worker to shut down.
func (w *DeliveryWorker) Stop() {
	if w == nil {
		return
	}
	close(w.done)
}

func (w *DeliveryWorker) poll() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deliveries, err := w.deliveryStore.PollPending(ctx, 10)
	if err != nil {
		log.Printf("WARN: poll pending deliveries failed: %v", err)
		return
	}

	for _, d := range deliveries {
		w.deliver(ctx, d)
	}
}

func (w *DeliveryWorker) deliver(ctx context.Context, d Delivery) {
	ep, err := w.endpointStore.GetByID(ctx, d.OrgID, d.EndpointID)
	if err != nil {
		log.Printf("WARN: get endpoint %s failed: %v", d.EndpointID, err)
		w.handleFailure(ctx, d, "endpoint not found: "+err.Error())
		return
	}

	var sendErr error
	switch ep.ChannelType {
	case "webhook":
		sendErr = w.webhook.Send(ctx, *ep, d.Payload)
	case "slack":
		sendErr = w.slack.Send(ctx, *ep, d.Payload)
	default:
		sendErr = nil // unknown channel type, mark as delivered to avoid retrying
		log.Printf("WARN: unknown channel type %q for endpoint %s", ep.ChannelType, ep.ID)
	}

	if sendErr == nil {
		if err := w.deliveryStore.MarkDelivered(ctx, d.ID); err != nil {
			log.Printf("WARN: mark delivery %s delivered failed: %v", d.ID, err)
		}
		return
	}

	w.handleFailure(ctx, d, sendErr.Error())
}

func (w *DeliveryWorker) handleFailure(ctx context.Context, d Delivery, errMsg string) {
	nextAttempt := d.Attempts + 1
	if nextAttempt >= d.MaxAttempts {
		log.Printf("WARN: delivery %s dead after %d attempts: %s", d.ID, nextAttempt, errMsg)
		if err := w.deliveryStore.MarkDead(ctx, d.ID, errMsg); err != nil {
			log.Printf("WARN: mark delivery %s dead failed: %v", d.ID, err)
		}
		return
	}

	// Exponential backoff: 30s, 1m, 5m, 15m, 60m
	backoffs := []time.Duration{
		30 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		60 * time.Minute,
	}
	idx := d.Attempts
	if idx >= len(backoffs) {
		idx = len(backoffs) - 1
	}
	nextTime := time.Now().Add(backoffs[idx])

	log.Printf("WARN: delivery %s attempt %d failed, retrying at %s: %s", d.ID, nextAttempt, nextTime.Format(time.RFC3339), errMsg)
	if err := w.deliveryStore.MarkFailed(ctx, d.ID, errMsg, nextTime); err != nil {
		log.Printf("WARN: mark delivery %s failed: %v", d.ID, err)
	}
}
