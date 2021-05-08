package duokey

import (
	"log"
	"os"
)

type Logger interface {
	Log(args ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (dl defaultLogger) Log(args ...interface{}) {
	dl.logger.Println(args...)
}

func NewDefaultLogger() Logger {
	return &defaultLogger{
		logger: log.New(os.Stdout, "DuoKey SDK", log.Ldate | log.Ltime | log.Llongfile),
	}
}