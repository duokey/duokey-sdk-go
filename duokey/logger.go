package duokey

import (
	"fmt"
	"log"
	"os"
)

// Logger is a generic logging interface. Zap SugaredLogger
// and Logrus automatically implement this interface
type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (dl defaultLogger) Info(args ...interface{}) {
	dl.logger.Output(2, fmt.Sprint(args...))
}

func (dl defaultLogger) Infof(format string, args ...interface{}) {
	dl.logger.Output(2, fmt.Sprintf(format, args...))
}

// NewDefaultLogger returns a Logger which will write log messages to stdout.
// Each log entry is prefixed with date, time, final file name element, and line number.
func NewDefaultLogger() Logger {
	return &defaultLogger{
		logger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
	}
}
