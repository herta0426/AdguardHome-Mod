package home

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDiscardFileName(t *testing.T) {
	testCases := []struct {
		name     string
		fileName string
		want     bool
	}{
		{name: "discard", fileName: configDiscard, want: true},
		{name: "discard_upper", fileName: "DISCARD", want: true},
		{name: "none", fileName: configNone, want: true},
		{name: "none_mixed", fileName: "None", want: true},
		{name: "syslog", fileName: configSyslog, want: false},
		{name: "empty", fileName: "", want: false},
		{name: "path", fileName: "/var/log/agh.log", want: false},
		{name: "discard_with_extension", fileName: "discard.log", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isDiscardFileName(tc.fileName))
		})
	}
}
