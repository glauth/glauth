//go:build windows
// +build windows

package logging

import (
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// We will use this package to wrap log messages coming from libraries who have no interest
// in generating structured output.

var (
	ldapliblogmatcher = regexp.MustCompile(`^\d{4}\/\d{1,2}\/\d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2} `)
)

func InitLogging(reqdebug bool, reqsyslog bool, reqstructlog bool) zerolog.Logger {
	var level zerolog.Level
	if reqdebug {
		level = zerolog.DebugLevel
	} else {
		level = zerolog.InfoLevel
	}

	var mainWriter io.Writer
	if reqstructlog {
		// Vroom vroom
		mainWriter = os.Stderr
		zerolog.TimeFieldFormat = time.RFC1123Z
	} else {
		// This is the inefficient writer
		mainWriter = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC1123Z}
	}

	logr := zerolog.New(mainWriter).Level(level).With().Timestamp().Logger()

	log.SetOutput(customWriter{logr: logr, structlog: reqstructlog})

	return logr
}

type customWriter struct {
	logr      zerolog.Logger
	structlog bool
}

func (e customWriter) Write(p []byte) (int, error) {
	submatchall := ldapliblogmatcher.FindAllString(string(p), 1)
	var msg string
	for _, element := range submatchall {
		msg = strings.TrimSpace(string(p[len(element):]))
	}
	if msg == "" {
		msg = strings.TrimSpace(string(p))
	}
	if e.structlog {
		fmt.Fprintf(os.Stderr, "{\"level\":\"info\",\"time\":\"%s\",\"message\":\"%s\"}\n", time.Now().Format(time.RFC1123Z), strings.Replace(strings.TrimSpace(msg), `"`, `\"`, -1))
	} else {
		e.logr.Info().Msg(msg)
	}
	return len(p), nil
}
