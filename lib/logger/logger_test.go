package logger

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2023, time.January, 1, 12, 0, 0, 0, time.UTC)

func TestPrettyHandler(t *testing.T) {
	tests := []struct {
		name     string
		level    slog.Level
		msg      string
		attrs    []slog.Attr
		expected string
	}{
		{
			name:     "debug level",
			level:    slog.LevelDebug,
			msg:      "debug message",
			attrs:    []slog.Attr{slog.String("key", "value")},
			expected: `value`,
		},
		{
			name:     "info level",
			level:    slog.LevelInfo,
			msg:      "info message",
			attrs:    []slog.Attr{slog.Int("count", 42)},
			expected: `count`,
		},
		{
			name:     "warn level",
			level:    slog.LevelWarn,
			msg:      "warn message",
			attrs:    []slog.Attr{slog.Bool("flag", true)},
			expected: `flag`,
		},
		{
			name:     "error level",
			level:    slog.LevelError,
			msg:      "error message",
			attrs:    []slog.Attr{slog.Float64("ratio", 3.14)},
			expected: `ratio`,
		},
		{
			name:     "no attributes",
			level:    slog.LevelInfo,
			msg:      "simple message",
			attrs:    []slog.Attr{},
			expected: `INFO: simple message`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts := PrettyHandlerOptions{
				SlogOpts: slog.HandlerOptions{
					Level: slog.LevelDebug,
				},
			}

			handler := newPrettyHandler(&buf, opts)

			// Отключаем цвета для тестов
			color.NoColor = true

			// Записываем лог
			record := slog.NewRecord(testTime, tt.level, tt.msg, 0)
			for _, attr := range tt.attrs {
				record.AddAttrs(attr)
			}

			err := handler.Handle(context.Background(), record)
			require.NoError(t, err)

			// Получаем вывод без временной метки
			output := buf.String()
			// Удаляем временную метку из вывода для сравнения
			output = output[24:] // удаляем "[01 Jan 23 12:00:00.000] "

			// Проверяем вывод
			assert.Contains(t, output, tt.expected)
		})
	}
}
