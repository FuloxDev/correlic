package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SSEWriter writes Server-Sent Events to an http.ResponseWriter.
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// NewSSEWriter creates a new SSE writer and sets the required headers.
// Returns nil if the ResponseWriter does not support flushing.
func NewSSEWriter(w http.ResponseWriter) *SSEWriter {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	return &SSEWriter{w: w, flusher: flusher}
}

// WriteDelta writes a text delta event.
func (s *SSEWriter) WriteDelta(delta string) {
	data, _ := json.Marshal(map[string]any{
		"type":    "delta",
		"content": delta,
	})
	fmt.Fprintf(s.w, "data: %s\n\n", string(data))
	s.flusher.Flush()
}

// WriteDone writes the completion event with token usage and model info.
func (s *SSEWriter) WriteDone(model string, inputTokens, outputTokens int) {
	data, _ := json.Marshal(map[string]any{
		"type":  "done",
		"model": model,
		"tokens": map[string]int{
			"input":  inputTokens,
			"output": outputTokens,
		},
	})
	fmt.Fprintf(s.w, "data: %s\n\n", string(data))
	s.flusher.Flush()
}

// WriteError writes an error event.
func (s *SSEWriter) WriteError(msg string) {
	data, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": msg,
	})
	fmt.Fprintf(s.w, "data: %s\n\n", string(data))
	s.flusher.Flush()
}

// jsonEscape escapes a string for safe inclusion in SSE data field.
func jsonEscape(s string) string {
	data, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(data)
}
