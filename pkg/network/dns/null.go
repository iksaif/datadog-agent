//+build windows linux_bpf

package dns

import (
	"inet.af/netaddr"
)

// NewNullReverseDNS returns a dummy implementation of ReverseDNS
func NewNullReverseDNS() ReverseDNS {
	return nullReverseDNS{}
}

type nullReverseDNS struct{}

func (nullReverseDNS) Resolve(_ []netaddr.IP) map[netaddr.IP][]string {
	return nil
}

func (nullReverseDNS) GetDNSStats() StatsByKeyByNameByType {
	return nil
}

func (nullReverseDNS) GetStats() map[string]int64 {
	return map[string]int64{
		"lookups":           0,
		"resolved":          0,
		"ips":               0,
		"added":             0,
		"expired":           0,
		"packets_received":  0,
		"packets_processed": 0,
		"packets_dropped":   0,
		"socket_polls":      0,
		"decoding_errors":   0,
	}
}

func (nullReverseDNS) Close() {}

var _ ReverseDNS = nullReverseDNS{}
