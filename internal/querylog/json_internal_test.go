package querylog

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
)

// TestQueryLog_entryToJSON_destination tests that the destination address of
// the connections recorded by the SNI filtering is exposed through the HTTP
// API.
func TestQueryLog_entryToJSON_destination(t *testing.T) {
	l := &queryLog{
		logger: slogutil.NewDiscardLogger(),
	}

	ctx := context.Background()
	anonFunc := func(net.IP) {}

	entry := &logEntry{
		Time:   time.Now(),
		QHost:  "example.org",
		QType:  "A",
		QClass: "IN",
		IP:     net.IPv4(192, 0, 2, 1),
		Dst:    "192.0.2.1:443",
		Result: filtering.Result{
			Reason:     filtering.FilteredSNI,
			IsFiltered: true,
		},
	}

	jsonEntry := l.entryToJSON(ctx, entry, anonFunc)
	assert.Equal(t, "192.0.2.1:443", jsonEntry["destination"])
	assert.Equal(t, "FilteredSNI", jsonEntry["reason"])

	// A regular DNS request has no destination.
	entry.Dst = ""
	jsonEntry = l.entryToJSON(ctx, entry, anonFunc)
	assert.Empty(t, jsonEntry["destination"])
}
