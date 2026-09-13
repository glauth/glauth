package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// customWriter adapts log output from libraries that emit unstructured text.
// Everything it receives must go through the logger, so that it lands wherever
// the logger points - notably syslog only, when syslog is enabled.
func TestCustomWriterEmitsValidJSONThroughTheLogger(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"plain", "something happened", "something happened"},
		{"quotes", `bind for "cn=foo"`, `bind for "cn=foo"`},
		{"backslashes", `path C:\Users\x`, `path C:\Users\x`},
		{"control characters", "tab\there\nand a newline", "tab\there\nand a newline"},
		{
			"library timestamp prefix is stripped",
			"2026/09/13 16:50:54 connection closed",
			"connection closed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := customWriter{logr: zerolog.New(&buf).With().Timestamp().Logger()}

			if _, err := w.Write([]byte(tc.in)); err != nil {
				t.Fatalf("Write: %v", err)
			}

			// One record, one line: an unescaped newline would split this.
			if got := strings.Count(strings.TrimRight(buf.String(), "\n"), "\n"); got != 0 {
				t.Fatalf("expected a single log line, got %d extra newlines in %q", got, buf.String())
			}

			var record struct {
				Level   string `json:"level"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
				t.Fatalf("emitted invalid JSON (%v): %s", err, buf.String())
			}
			if record.Message != tc.want {
				t.Errorf("message = %q, want %q", record.Message, tc.want)
			}
			if record.Level != "info" {
				t.Errorf("level = %q, want %q", record.Level, "info")
			}
		})
	}
}
