package event

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func GenerateID(
	hostID string,
	tsNano int64,
	source string,
	eventType string,
	pid int,
	target string,
) string {

	raw := fmt.Sprintf(
		"%s|%d|%s|%s|%d|%s",
		hostID,
		tsNano,
		source,
		eventType,
		pid,
		target,
	)

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
