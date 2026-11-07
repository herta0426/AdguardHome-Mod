package snifilter

import (
	"testing"

	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v4"
)

// TestLegacyUIDsFieldIgnored proves that removing the UIDs field from the
// Params struct does not break loading of an older configuration that still
// contains the old "uids" key: it must be unmarshaled without an error, with
// the field simply ignored.
func TestLegacyUIDsFieldIgnored(t *testing.T) {
	const data = `
queue_num: 7
ports: [443]
uids:
  - 10000-19999
drop_quic: false
`

	var p Params
	err := yaml.Unmarshal([]byte(data), &p)
	require.NoError(t, err)

	require.Equal(t, uint16(7), p.QueueNum)
	require.Equal(t, []uint16{443}, p.Ports)
	require.False(t, p.DropQUIC)
}
