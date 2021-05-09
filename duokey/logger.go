package duokey

import (
	"log"
	"os"
)

// https://dave.cheney.net/tag/logging

// Logger is a generic logging interface. Zap SugaredLogger and Logrus automatically implement
// this interface
type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (dl defaultLogger) Info(args ...interface{}) {
	dl.logger.Println(args...)
}

func (dl defaultLogger) Infof(format string, args ...interface{}) {
	dl.logger.Printf(format, args...)
}

func NewDefaultLogger() Logger {
	return &defaultLogger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}
