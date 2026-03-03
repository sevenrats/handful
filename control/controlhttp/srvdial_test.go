// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlhttp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/types/logger"
)

// mockSRVResolver implements srvResolver for testing.
type mockSRVResolver struct {
	srvRecords map[string][]*net.SRV // keyed by "service.proto.name"
	ipRecords  map[string][]net.IPAddr
	srvErr     error
	ipErr      map[string]error
}

func (m *mockSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if m.srvErr != nil {
		return "", nil, m.srvErr
	}
	key := fmt.Sprintf("%s.%s.%s", service, proto, name)
	return "", m.srvRecords[key], nil
}

func (m *mockSRVResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if m.ipErr != nil {
		if err, ok := m.ipErr[host]; ok {
			return nil, err
		}
	}
	return m.ipRecords[host], nil
}

func TestLookupControlSRV(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		resolver   *mockSRVResolver
		wantCount  int
		wantErr    bool
		wantPorts  []uint16
		wantPriorities []int
	}{
		{
			name:     "no SRV records",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{},
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:     "SRV lookup error",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvErr: fmt.Errorf("DNS lookup failed"),
			},
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:     "single SRV record with one IP",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{
					"ts2021.tcp.controlplane.example.com": {
						{Target: "server1.example.com.", Port: 8443, Priority: 0, Weight: 100},
					},
				},
				ipRecords: map[string][]net.IPAddr{
					"server1.example.com.": {
						{IP: net.ParseIP("192.168.1.1")},
					},
				},
			},
			wantCount:  1,
			wantErr:    false,
			wantPorts:  []uint16{8443},
			wantPriorities: []int{0}, // maxPri=0, inverted: 0-0=0
		},
		{
			name:     "multiple SRV records with priority inversion",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{
					"ts2021.tcp.controlplane.example.com": {
						{Target: "primary.example.com.", Port: 443, Priority: 0, Weight: 100},
						{Target: "backup.example.com.", Port: 8443, Priority: 10, Weight: 50},
					},
				},
				ipRecords: map[string][]net.IPAddr{
					"primary.example.com.": {
						{IP: net.ParseIP("10.0.0.1")},
					},
					"backup.example.com.": {
						{IP: net.ParseIP("10.0.0.2")},
					},
				},
			},
			wantCount:  2,
			wantErr:    false,
			wantPorts:  []uint16{443, 8443},
			wantPriorities: []int{10, 0}, // maxPri=10: primary 10-0=10, backup 10-10=0
		},
		{
			name:     "SRV target with multiple IPs",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{
					"ts2021.tcp.controlplane.example.com": {
						{Target: "multi.example.com.", Port: 443, Priority: 5, Weight: 100},
					},
				},
				ipRecords: map[string][]net.IPAddr{
					"multi.example.com.": {
						{IP: net.ParseIP("10.0.0.1")},
						{IP: net.ParseIP("10.0.0.2")},
						{IP: net.ParseIP("2001:db8::1")},
					},
				},
			},
			wantCount:  3,
			wantErr:    false,
			wantPorts:  []uint16{443, 443, 443},
			wantPriorities: []int{0, 0, 0}, // maxPri=5, 5-5=0
		},
		{
			name:     "SRV target IP resolution failure is non-fatal",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{
					"ts2021.tcp.controlplane.example.com": {
						{Target: "good.example.com.", Port: 443, Priority: 0, Weight: 100},
						{Target: "bad.example.com.", Port: 8443, Priority: 10, Weight: 50},
					},
				},
				ipRecords: map[string][]net.IPAddr{
					"good.example.com.": {
						{IP: net.ParseIP("10.0.0.1")},
					},
				},
				ipErr: map[string]error{
					"bad.example.com.": fmt.Errorf("NXDOMAIN"),
				},
			},
			wantCount:  1,
			wantErr:    false,
			wantPorts:  []uint16{443},
			wantPriorities: []int{10}, // maxPri=10, 10-0=10
		},
		{
			name:     "empty target is skipped",
			hostname: "controlplane.example.com",
			resolver: &mockSRVResolver{
				srvRecords: map[string][]*net.SRV{
					"ts2021.tcp.controlplane.example.com": {
						{Target: "", Port: 443, Priority: 0, Weight: 100},
						{Target: "real.example.com.", Port: 8443, Priority: 5, Weight: 50},
					},
				},
				ipRecords: map[string][]net.IPAddr{
					"real.example.com.": {
						{IP: net.ParseIP("10.0.0.1")},
					},
				},
			},
			wantCount:  1,
			wantErr:    false,
			wantPorts:  []uint16{8443},
			wantPriorities: []int{0}, // maxPri=5, 5-5=0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates, err := lookupControlSRV(
				context.Background(),
				tt.hostname,
				logger.Discard,
				tt.resolver,
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("lookupControlSRV() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if len(candidates) != tt.wantCount {
				t.Fatalf("got %d candidates, want %d; candidates=%+v", len(candidates), tt.wantCount, candidates)
			}
			for i, c := range candidates {
				if i < len(tt.wantPorts) && c.Port != tt.wantPorts[i] {
					t.Errorf("candidate[%d].Port = %d, want %d", i, c.Port, tt.wantPorts[i])
				}
				if i < len(tt.wantPriorities) && c.Priority != tt.wantPriorities[i] {
					t.Errorf("candidate[%d].Priority = %d, want %d", i, c.Priority, tt.wantPriorities[i])
				}
				// Every candidate should have a valid IP
				if !c.IP.IsValid() {
					t.Errorf("candidate[%d].IP is not valid", i)
				}
				// Every candidate should have a 10s timeout
				if c.DialTimeoutSec != 10 {
					t.Errorf("candidate[%d].DialTimeoutSec = %v, want 10", i, c.DialTimeoutSec)
				}
			}
		})
	}
}

func TestLookupControlSRVIPAddresses(t *testing.T) {
	// Verify that IPv4-mapped IPv6 addresses are properly unmapped.
	resolver := &mockSRVResolver{
		srvRecords: map[string][]*net.SRV{
			"ts2021.tcp.example.com": {
				{Target: "host.example.com.", Port: 443, Priority: 0, Weight: 100},
			},
		},
		ipRecords: map[string][]net.IPAddr{
			"host.example.com.": {
				{IP: net.ParseIP("::ffff:192.168.1.1")}, // IPv4-mapped IPv6
				{IP: net.ParseIP("192.168.1.2")},
			},
		},
	}

	candidates, err := lookupControlSRV(context.Background(), "example.com", logger.Discard, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(candidates))
	}

	// Both should be IPv4 after Unmap
	want1 := netip.MustParseAddr("192.168.1.1")
	want2 := netip.MustParseAddr("192.168.1.2")
	if candidates[0].IP != want1 {
		t.Errorf("candidate[0].IP = %v, want %v", candidates[0].IP, want1)
	}
	if candidates[1].IP != want2 {
		t.Errorf("candidate[1].IP = %v, want %v", candidates[1].IP, want2)
	}
}
