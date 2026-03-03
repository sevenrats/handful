// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlhttp

import (
	"context"
	"math"
	"net"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// srvResolver is the interface used for DNS SRV lookups, allowing injection
// of a mock resolver in tests.
type srvResolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// netSRVResolver wraps *net.Resolver to implement srvResolver.
type netSRVResolver struct {
	*net.Resolver
}

// defaultSRVResolver returns a new netSRVResolver using the Go DNS resolver.
func defaultSRVResolver() srvResolver {
	return &netSRVResolver{
		Resolver: &net.Resolver{PreferGo: true},
	}
}

// lookupControlSRV performs a DNS SRV lookup for _ts2021._tcp.<hostname> and
// resolves the returned targets into ControlIPCandidate entries suitable for
// merging into the dial plan.
//
// SRV Priority values are mapped to ControlIPCandidate.Priority; lower SRV
// priority numbers mean higher preference, which matches the convention for
// ControlIPCandidate where higher Priority values are preferred. We apply
// the inversion so that SRV priority 0 gets the highest ControlIPCandidate
// priority.
//
// Each resolved IP address gets its own candidate entry, with a default
// 10-second dial timeout and no initial delay (they are raced in parallel
// with other candidates).
//
// If the SRV lookup itself fails, nil candidates and the error are returned.
// Individual target resolution failures are logged but do not cause the
// entire lookup to fail.
func lookupControlSRV(ctx context.Context, hostname string, logf logger.Logf, resolver srvResolver) ([]tailcfg.ControlIPCandidate, error) {
	if resolver == nil {
		resolver = defaultSRVResolver()
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, srvRecords, err := resolver.LookupSRV(lookupCtx, "ts2021", "tcp", hostname)
	if err != nil {
		return nil, err
	}
	if len(srvRecords) == 0 {
		return nil, nil
	}

	// Find the maximum SRV priority value so we can invert: lower SRV
	// priority numbers should map to higher ControlIPCandidate.Priority.
	var maxSRVPriority uint16
	for _, srv := range srvRecords {
		if srv.Priority > maxSRVPriority {
			maxSRVPriority = srv.Priority
		}
	}

	var candidates []tailcfg.ControlIPCandidate
	for _, srv := range srvRecords {
		if srv.Target == "" {
			continue
		}
		ips, err := resolver.LookupIPAddr(lookupCtx, srv.Target)
		if err != nil {
			logf("[v1] controlhttp: SRV target %q lookup failed: %v", srv.Target, err)
			continue
		}
		// Invert SRV priority: SRV 0 (highest pref) → highest ControlIPCandidate priority.
		invertedPriority := int(maxSRVPriority) - int(srv.Priority)
		if invertedPriority < 0 {
			invertedPriority = 0
		}
		// Clamp to int range for safety.
		if invertedPriority > math.MaxInt32 {
			invertedPriority = math.MaxInt32
		}

		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			candidates = append(candidates, tailcfg.ControlIPCandidate{
				IP:                addr,
				Port:              srv.Port,
				DialStartDelaySec: 0,
				DialTimeoutSec:    10,
				Priority:          invertedPriority,
			})
		}
	}

	logf("[v1] controlhttp: SRV lookup for %q returned %d candidates", hostname, len(candidates))
	return candidates, nil
}
