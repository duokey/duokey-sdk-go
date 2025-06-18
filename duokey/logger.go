package duokey

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Logger is a generic logging interface. Zap SugaredLogger
// and Logrus automatically implement this interface
type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Debug(...interface{})
	Debugf(string, ...interface{})
	Warning(...interface{})
	Warningf(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
}

func LogExecutionTime(logger Logger, msg string, start time.Time) {
	logger.Infof("%s: %s", msg, time.Since(start))
}

// defaultLogger where all logs are logger.Output
type defaultLogger struct {
	logger *log.Logger
}

func (dl defaultLogger) Info(args ...interface{}) {
	dl.logger.Output(2, fmt.Sprint(args...))
}

func (dl defaultLogger) Infof(format string, args ...interface{}) {
	dl.logger.Output(2, fmt.Sprintf(format, args...))
}

func (dl defaultLogger) Debug(args ...interface{}) {
	dl.logger.Output(2, fmt.Sprint(args...))
}

func (dl defaultLogger) Debugf(format string, args ...interface{}) {
	dl.logger.Output(2, fmt.Sprintf(format, args...))
}
func (dl defaultLogger) Error(args ...interface{}) {
	dl.logger.Output(2, fmt.Sprint(args...))
}

func (dl defaultLogger) Errorf(format string, args ...interface{}) {
	dl.logger.Output(2, fmt.Sprintf(format, args...))
}

func (dl defaultLogger) Warning(args ...interface{}) {
	dl.logger.Output(2, fmt.Sprint(args...))
}

func (dl defaultLogger) Warningf(format string, args ...interface{}) {
	dl.logger.Output(2, fmt.Sprintf(format, args...))
}

// NewDefaultLogger returns a Logger which will write log messages to stdout.
// Each log entry is prefixed with date, time, final file name element, and line number.
func NewDefaultLogger() Logger {
	return &defaultLogger{
		logger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
	}
}
