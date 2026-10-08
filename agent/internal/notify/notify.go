package notify

import (
	"log/slog"
	"os/exec"
	"runtime"
)

// Local sends a best-effort local notification.
// On Linux, tries `notify-send` if available; otherwise logs.
func Local(title, body string) {
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("notify-send"); err == nil {
			// best-effort; ignore failures (no display, no dbus, etc)
			_ = exec.Command("notify-send", title, body).Run()
			return
		}
	}
	slog.Info("notification", "title", title, "body", body)
}
