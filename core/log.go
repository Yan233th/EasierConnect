package core

import (
	"fmt"
	"time"

	"github.com/gookit/color"
)

// DisableColor disables colored output globally
func DisableColor() {
	color.Disable()
}

// timestamp returns current time in log format
func timestamp() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

// Log prints a message with colored tag
// tag: [VPN], [LOGIN], etc. (cyan)
// message: the rest of the log line (default color)
func Log(tag string, format string, args ...interface{}) {
	fmt.Print(timestamp() + " ")
	color.Cyan.Print(tag + " ")
	fmt.Printf(format+"\n", args...)
}

// LogSuccess prints a success message with colored tag and green content
// tag: [VPN], [LOGIN], etc. (cyan)
// message: ✓ ... (green)
func LogSuccess(tag string, format string, args ...interface{}) {
	fmt.Print(timestamp() + " ")
	color.Cyan.Print(tag + " ")
	color.Green.Printf(format+"\n", args...)
}

// LogWarn prints a warning message in yellow
// format: [WARN] ...
func LogWarn(format string, args ...interface{}) {
	fmt.Print(timestamp() + " ")
	color.Yellow.Printf("[WARN] "+format+"\n", args...)
}

// LogError prints an error message in red
// format: message
func LogError(format string, args ...interface{}) {
	fmt.Print(timestamp() + " ")
	color.Red.Printf(format+"\n", args...)
}
