package gatekeeper

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
)

type rusLogger struct {
	Logger *logrus.Logger
}

func NewLogger(logger *logrus.Logger) func(next http.Handler) http.Handler {
	if logger == nil {
		// kind of a hack
		logger = logrus.WithError(nil).Logger
	}
	return middleware.RequestLogger(&rusLogger{logger})
}

func (l *rusLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	entry := &rusLoggerEntry{Logger: logrus.NewEntry(l.Logger)}
	logFields := logrus.Fields{}

	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		logFields["req_id"] = reqID
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	logFields["scheme"] = scheme
	logFields["proto"] = r.Proto
	logFields["method"] = r.Method

	logFields["remote_addr"] = r.RemoteAddr
	logFields["user_agent"] = r.UserAgent()

	logFields["uri"] = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	if r.Header.Get("Peer-Checker") == "true" && r.RequestURI == "/status" {
		logFields["peer_check"] = true
	}

	entry.Logger = entry.Logger.WithFields(logFields)

	return entry
}

type rusLoggerEntry struct {
	Logger logrus.FieldLogger
}

func (l *rusLoggerEntry) Write(status, bytes int, elapsed time.Duration) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"status":     status,
		"length":     bytes,
		"elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})

	if e, ok := l.Logger.(*logrus.Entry); ok {
		if b, ok := e.Data["peer_check"].(bool); ok && b {
			l.Logger.Debugln("request completed for peer check")
			return
		}
	}
	if status >= 500 {
		l.Logger.Errorln("request completed with error")
	} else {
		l.Logger.Infoln("request completed")
	}
}

func (l *rusLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
	fmt.Fprintf(os.Stderr, "Panic: %+v\n", v)
	os.Stderr.Write(stack)
}

// Helper methods used by the application to get the request-scoped
// logger entry and set additional fields between handlers.
//
// This is a useful pattern to use to set state on the entry as it
// passes through the handler chain, which at any point can be logged
// with a call to .Print(), .Info(), etc.

func GetLog(r *http.Request) logrus.FieldLogger {
	entry := middleware.GetLogEntry(r).(*rusLoggerEntry)
	return entry.Logger
}

func LogEntrySetField(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*rusLoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
	}
}

func LogEntrySetFields(r *http.Request, fields map[string]interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*rusLoggerEntry); ok {
		entry.Logger = entry.Logger.WithFields(fields)
	}
}
