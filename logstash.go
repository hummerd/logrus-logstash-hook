package logrus_logstash

import (
	"bytes"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
)

var (
	entryChan  chan sendMessage    = make(chan sendMessage, 1000)
	formatBuff sync.Pool           = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
	connPool   map[string]net.Conn = make(map[string]net.Conn, 1)
)

func init() {
	go processEntryData(entryChan)
}

type sendMessage struct {
	protocol string
	address  string
	data     *bytes.Buffer
}

// Hook represents a connection to a Logstash instance
type Hook struct {
	protocol         string
	address          string
	filtering        bool
	appName          string
	alwaysSentFields logrus.Fields
	hookOnlyPrefix   string
}

// NewHook creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`.
func NewHook(protocol, address, appName string) *Hook {
	return NewHookWithFields(protocol, address, appName, make(logrus.Fields))
}

// NewHookWithFields creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry.
func NewHookWithFields(protocol, address, appName string, alwaysSentFields logrus.Fields) *Hook {
	return NewHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, "")
}

//NewHookWithFieldsAndConnAndPrefix creates a new hook to a Logstash instance using the suppolied connection and prefix
func NewHookWithFieldsAndPrefix(protocol, address, appName string, alwaysSentFields logrus.Fields, prefix string) *Hook {
	return &Hook{protocol: protocol, address: address, filtering: false, appName: appName, alwaysSentFields: alwaysSentFields, hookOnlyPrefix: prefix}
}

//NewFilterHook makes a new hook which does not forward to logstash, but simply enforces the prefix rules
func NewFilterHook() *Hook {
	return NewFilterHookWithPrefix("")
}

//NewFilterHookWithPrefix make a new hook which does not forward to logstash, but simply enforces the specified prefix
func NewFilterHookWithPrefix(prefix string) *Hook {
	return &Hook{filtering: true, appName: "", alwaysSentFields: make(logrus.Fields), hookOnlyPrefix: prefix}
}

func (h *Hook) filterHookOnly(entry *logrus.Entry) {
	if h.hookOnlyPrefix != "" {
		for key := range entry.Data {
			if strings.HasPrefix(key, h.hookOnlyPrefix) {
				delete(entry.Data, key)
			}
		}
	}
}

//WithPrefix sets a prefix filter to use in all subsequent logging
func (h *Hook) WithPrefix(prefix string) {
	h.hookOnlyPrefix = prefix
}

func (h *Hook) WithField(key string, value interface{}) {
	h.alwaysSentFields[key] = value
}

func (h *Hook) WithFields(fields logrus.Fields) {
	//Add all the new fields to the 'alwaysSentFields', possibly overwriting exising fields
	for key, value := range fields {
		h.alwaysSentFields[key] = value
	}
}

func (h *Hook) Fire(entry *logrus.Entry) error {
	//make sure we always clear the hookonly fields from the entry
	defer h.filterHookOnly(entry)

	// Add in the alwaysSentFields. We don't override fields that are already set.
	for k, v := range h.alwaysSentFields {
		if _, inMap := entry.Data[k]; !inMap {
			entry.Data[k] = v
		}
	}

	//For a filteringHook, stop here
	if h.filtering {
		return nil
	}

	buff := getFormatBuf()

	writer := LogstashWriter{Type: h.appName}
	err := writer.WriteWithPrefix(buff, entry, h.hookOnlyPrefix)
	if err != nil {
		return err
	}

	select {
	case entryChan <- sendMessage{h.protocol, h.address, buff}:
	default:
	}

	return nil
}

func (h *Hook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

func getFormatBuf() *bytes.Buffer {
	b := formatBuff.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func processEntryData(data chan sendMessage) {
	for d := range data {
		_, err := sendDataAndRetry(d)
		formatBuff.Put(d.data)
		if err != nil {
			os.Stderr.WriteString("Error sending data to logstash: " + err.Error())
		}
	}
}

func sendDataAndRetry(data sendMessage) (int, error) {
	conn := connPool[data.protocol+":"+data.address]
	if conn != nil {
		if n, err := conn.Write(data.data.Bytes()); err == nil {
			return n, err
		}
	}

	conn, err := net.Dial(data.protocol, data.address)
	if err != nil {
		return 0, err
	}

	connPool[data.protocol+":"+data.address] = conn
	return conn.Write(data.data.Bytes())
}
