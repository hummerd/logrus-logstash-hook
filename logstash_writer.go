package logrus_logstash

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
)

// Formatter generates json in logstash format.
// Logstash site: http://logstash.net/
type LogstashWriter struct {
	Type string // if not empty use for logstash type field.

	// TimestampFormat sets the format used for timestamps.
	TimestampFormat string
}

func (w *LogstashWriter) Write(writer io.Writer, entry *logrus.Entry) error {
	return w.WriteWithPrefix(writer, entry, "")
}

func (w *LogstashWriter) WriteWithPrefix(writer io.Writer, entry *logrus.Entry, prefix string) error {
	fields := make(logrus.Fields)
	for k, v := range entry.Data {
		//remvove the prefix when sending the fields to logstash
		if prefix != "" && strings.HasPrefix(k, prefix) {
			k = strings.TrimPrefix(k, prefix)
		}

		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/sirupsen/logrus/issues/377
			fields[k] = v.Error()
		default:
			fields[k] = v
		}
	}

	fields["@version"] = "1"

	timeStampFormat := w.TimestampFormat

	if timeStampFormat == "" {
		timeStampFormat = defaultTimestampFormat
	}

	fields["@timestamp"] = entry.Time.Format(timeStampFormat)

	// set message field
	v, ok := entry.Data["message"]
	if ok {
		fields["fields.message"] = v
	}
	fields["message"] = entry.Message

	// set level field
	v, ok = entry.Data["level"]
	if ok {
		fields["fields.level"] = v
	}
	fields["level"] = entry.Level.String()

	// set type field
	if w.Type != "" {
		v, ok = entry.Data["type"]
		if ok {
			fields["fields.type"] = v
		}
		fields["type"] = w.Type
	}

	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(fields); err != nil {
		return fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}

	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}

	return nil
}
