package filtering

import (
	"fmt"
	"maps"
)

// Reason holds an enum detailing why it was filtered, allowed, or rewritten.
type Reason uint8

const (
	// NotFilteredNotFound: the host was not find in any checks, default value
	// for results.
	NotFilteredNotFound Reason = iota

	// NotFilteredAllowList: the host is explicitly allowed.
	NotFilteredAllowList

	// NotFilteredError is returned when there was an error during checking.
	// Reserved, currently unused.
	NotFilteredError

	// FilteredBlockList: the host was matched to be advertising host.
	FilteredBlockList

	// FilteredSafeBrowsing: the host was matched to be malicious/phishing.
	FilteredSafeBrowsing

	// FilteredParental: the host was matched to be outside of parental control
	// settings.
	FilteredParental

	// FilteredInvalid: the request was invalid and was not processed.
	FilteredInvalid

	// The values 7 and 8 are reserved.  They were used by the removed safe
	// search and blocked services filters and are kept as placeholders to
	// preserve the numbering of the reasons stored in the query log.
	_ // FilteredSafeSearch
	_ // FilteredBlockedService

	// Rewritten is returned when there was a rewrite by a legacy DNS rewrite
	// rule.
	Rewritten

	// RewrittenAutoHosts is returned when there was a rewrite by /etc/hosts.
	RewrittenAutoHosts

	// RewrittenRule is returned when a $dnsrewrite filter rule was applied.
	//
	// TODO(a.garipov): Remove [Rewritten] and [RewrittenAutoHosts] by merging
	// their functionality into RewrittenRule.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2499.
	RewrittenRule

	// FilteredSNI is returned when a TLS connection was blocked by its SNI
	// value by the SNI filtering of the TLS connections.  It's a mod-only
	// reason.
	//
	// It's appended to the end of the list and not put next to the other
	// filtered reasons to keep the numbers of the existing ones stable, since
	// they are stored in the query log files and in the statistics files.
	FilteredSNI

	// NotFilteredSNI is returned when a TLS connection was inspected by its SNI
	// value by the SNI filtering of the TLS connections and allowed.  It's a
	// mod-only reason, appended to the end of the list for the same reason as
	// [FilteredSNI]: to keep the numbers of the existing reasons stable.
	NotFilteredSNI
)

// reasonNames maps reason values to their string representations.
//
// TODO(a.garipov): Resync with actual code names or replace completely in the
// next version of HTTP API.
var reasonNames = []string{
	NotFilteredNotFound:  "NotFilteredNotFound",
	NotFilteredAllowList: "NotFilteredWhiteList",
	NotFilteredError:     "NotFilteredError",

	FilteredBlockList:    "FilteredBlackList",
	FilteredSafeBrowsing: "FilteredSafeBrowsing",
	FilteredParental:     "FilteredParental",
	FilteredInvalid:      "FilteredInvalid",

	Rewritten:          "Rewrite",
	RewrittenAutoHosts: "RewriteEtcHosts",
	RewrittenRule:      "RewriteRule",

	FilteredSNI:    "FilteredSNI",
	NotFilteredSNI: "NotFilteredSNI",
}

// ReasonByName maps reason string names to their values.
var ReasonByName = maps.Collect(func(yield func(string, Reason) (ok bool)) {
	for i, name := range reasonNames {
		if name == "" {
			// Skip the reserved values.
			continue
		}

		if !yield(name, Reason(i)) {
			break
		}
	}
})

// type check
var _ fmt.Stringer = NotFilteredNotFound

// String implements the [fmt.Stringer] interface for Reason.
func (r Reason) String() (s string) {
	if int(r) >= len(reasonNames) {
		return ""
	}

	return reasonNames[r]
}
