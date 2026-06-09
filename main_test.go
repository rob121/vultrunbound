package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFormatHosts(t *testing.T) {
	entries := []DnsEntry{
		{Name: "host.example.com", ShortName: "host", Address: "203.0.113.10", Device: "eth0"},
		{Name: "hosti.example.com", ShortName: "hosti", Address: "10.0.0.10", Device: "eth1"},
	}

	got := FormatHosts(entries, "no")
	want := "203.0.113.10 host host.example.com\n" +
		"10.0.0.10 hosti hosti.example.com\n" +
		"127.0.0.1 localhost.localdomain localhost4 localhost4.localdomain4 localhost\n" +
		"127.0.0.1 localhost.localdomain localhost6 localhost6.localdomain6 localhost\n"

	if got != want {
		t.Fatalf("FormatHosts() = %q, want %q", got, want)
	}
}

func TestServerEndpointDefaultsToHTTPAndPort(t *testing.T) {
	oldClient := client
	client = "192.168.4.1"
	t.Cleanup(func() {
		client = oldClient
	})

	got, err := ServerEndpoint("/entries", nil)
	if err != nil {
		t.Fatal(err)
	}

	want := "http://192.168.4.1:8080/entries"
	if got != want {
		t.Fatalf("ServerEndpoint() = %q, want %q", got, want)
	}
}

func TestVultrDNSRoundTrip(t *testing.T) {
	oldVultrDNS := vultrdns
	vultrdns = filepath.Join(t.TempDir(), ".vultrdns")
	t.Cleanup(func() {
		vultrdns = oldVultrDNS
	})

	entries := []DnsEntry{
		{Name: "host.example.com", ShortName: "host", Address: "203.0.113.10", Device: "eth0"},
	}

	if err := SaveVultrDNS(entries); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(vultrdns); err != nil {
		t.Fatal(err)
	}

	got, err := LoadVultrDNS()
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0] != entries[0] {
		t.Fatalf("LoadVultrDNS() = %#v, want %#v", got, entries)
	}
}

func TestSetModifiedAtHeader(t *testing.T) {
	oldVultrDNS := vultrdns
	vultrdns = filepath.Join(t.TempDir(), ".vultrdns")
	t.Cleanup(func() {
		vultrdns = oldVultrDNS
	})

	if err := SaveVultrDNS([]DnsEntry{}); err != nil {
		t.Fatal(err)
	}

	modifiedAt := time.Date(2026, 6, 9, 12, 34, 56, 0, time.UTC)
	if err := os.Chtimes(vultrdns, modifiedAt, modifiedAt); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	setModifiedAtHeader(recorder)

	got := recorder.Header().Get("X-ModifiedAt")
	want := "2026-06-09T12:34:56Z"
	if got != want {
		t.Fatalf("X-ModifiedAt = %q, want %q", got, want)
	}
}
