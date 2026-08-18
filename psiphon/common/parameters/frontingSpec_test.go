/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package parameters

import "testing"

func TestFrontedMeekDialOverrideSpecs(t *testing.T) {

	overrides := FrontedMeekDialOverrideSpecs{
		&FrontedMeekDialOverride{
			OverrideID:                     "fastly",
			MatchFrontingProviderIDRegexes: []string{"(?i)fastly"},
			MatchDialAddressRegexes:        []string{`\.fastly\.net$`},
			DialAddresses:                  []string{"pypi.org"},
			SNIServerName:                  "pypi.org",
			VerifyServerNames:              []string{"pypi.org", "fastly.com"},
			VerifyPins:                     []string{"pin"},
			ALPNProtocols:                  []string{"h2", "http/1.1"},
		},
		&FrontedMeekDialOverride{
			OverrideID:              "fallback",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"fallback.example.org"},
			VerifyServerNames:       []string{"fallback.example.org"},
		},
	}

	err := overrides.Validate(nil)
	if err != nil {
		t.Fatalf("Validate failed: %s", err)
	}

	override, ok, err := overrides.SelectParameters(
		"FASTLY", []string{"example.fastly.net"}, "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if !ok {
		t.Fatalf("missing selected override")
	}

	if override.OverrideID != "fastly" ||
		override.DialAddress != "pypi.org" ||
		override.SNIServerName != "pypi.org" ||
		len(override.VerifyServerNames) != 2 ||
		override.VerifyServerNames[0] != "pypi.org" ||
		len(override.VerifyPins) != 1 ||
		override.VerifyPins[0] != "pin" ||
		len(override.ALPNProtocols) != 2 ||
		override.ALPNProtocols[0] != "h2" {
		t.Fatalf("unexpected override: %+v", override)
	}

	override, ok, err = overrides.SelectParameters(
		"AKAMAI", []string{"example.fastly.net"}, "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if !ok {
		t.Fatalf("missing fallback override")
	}
	if override.OverrideID != "fallback" ||
		override.DialAddress != "fallback.example.org" {
		t.Fatalf("unexpected fallback override: %+v", override)
	}

	strictOverrides := FrontedMeekDialOverrideSpecs{overrides[0]}
	_, ok, err = strictOverrides.SelectParameters(
		"AKAMAI", []string{"example.fastly.net"}, "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if ok {
		t.Fatalf("unexpected selected override")
	}
}

func TestFrontedMeekDialOverrideSpecsSelectCandidateParameters(t *testing.T) {

	overrides := FrontedMeekDialOverrideSpecs{
		&FrontedMeekDialOverride{
			OverrideID:              "preferred",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"preferred-1.example.org", "preferred-2.example.org"},
			VerifyServerNames:       []string{"preferred.example.org"},
		},
		&FrontedMeekDialOverride{
			OverrideID:              "fallback",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"fallback.example.org"},
			VerifyServerNames:       []string{"fallback.example.org"},
		},
	}

	expected := []struct {
		candidateNumber int
		overrideID      string
		dialAddress     string
	}{
		{0, "preferred", "preferred-1.example.org"},
		{1, "preferred", "preferred-2.example.org"},
		{2, "fallback", "fallback.example.org"},
		{3, "preferred", "preferred-1.example.org"},
	}

	for _, expectedCandidate := range expected {
		override, ok, err := overrides.SelectCandidateParameters(
			"CDN", []string{"front.example"}, "host.example",
			expectedCandidate.candidateNumber)
		if err != nil {
			t.Fatalf("SelectCandidateParameters failed: %s", err)
		}
		if !ok {
			t.Fatalf("missing selected override")
		}
		if override.OverrideID != expectedCandidate.overrideID ||
			override.DialAddress != expectedCandidate.dialAddress {
			t.Fatalf(
				"candidate %d selected %+v, expected %s/%s",
				expectedCandidate.candidateNumber,
				override,
				expectedCandidate.overrideID,
				expectedCandidate.dialAddress)
		}
	}
}

func TestFrontedMeekCDNScanSpec(t *testing.T) {

	spec := FrontedMeekCDNScanSpec{
		IPCandidates: []string{
			"192.0.2.1",
			"192.0.2.8/30",
			"192.0.2.1",
		},
		SNIServerNames: []string{
			"Example.COM",
			"cdn.example.com",
			"example.com.",
		},
	}

	if err := spec.Validate(); err != nil {
		t.Fatalf("Validate failed: %s", err)
	}

	if count := spec.CandidateCount(); count != 15 {
		t.Fatalf("unexpected candidate count: %d", count)
	}

	if count := spec.SNIServerNameCount(); count != 2 {
		t.Fatalf("unexpected SNI count: %d", count)
	}

	seen := make(map[string]struct{})
	emptySNICount := 0
	for i := 0; i < spec.CandidateCount(); i++ {
		candidate, ok, err := spec.SelectCandidate(i, nil)
		if err != nil {
			t.Fatalf("SelectCandidate failed: %s", err)
		}
		if !ok {
			t.Fatalf("missing candidate")
		}
		if candidate.SNIServerName == "" {
			emptySNICount += 1
		}
		if candidate.SNIServerName == candidate.IPAddress {
			t.Fatalf("IP address selected as SNI: %+v", candidate)
		}
		seen[candidate.Key()] = struct{}{}
	}
	if len(seen) != spec.CandidateCount() {
		t.Fatalf("unexpected unique candidate count: %d", len(seen))
	}
	if emptySNICount != 5 {
		t.Fatalf("unexpected empty SNI candidate count: %d", emptySNICount)
	}

	noSNISpec := FrontedMeekCDNScanSpec{
		IPCandidates: []string{"192.0.2.1", "192.0.2.2"},
	}
	if count := noSNISpec.CandidateCount(); count != 2 {
		t.Fatalf("unexpected no-SNI candidate count: %d", count)
	}
	for i := 0; i < noSNISpec.CandidateCount(); i++ {
		candidate, ok, err := noSNISpec.SelectCandidate(i, nil)
		if err != nil || !ok {
			t.Fatalf("SelectCandidate for no-SNI spec failed: %v", err)
		}
		if candidate.SNIServerName != "" {
			t.Fatalf("unexpected SNI for no-SNI spec: %+v", candidate)
		}
	}

	firstCandidate, ok, err := spec.SelectCandidate(0, nil)
	if err != nil || !ok {
		t.Fatalf("SelectCandidate failed: %v", err)
	}
	skipped := map[string]struct{}{
		firstCandidate.Key(): {},
	}
	secondCandidate, ok, err := spec.SelectCandidate(0, skipped)
	if err != nil || !ok {
		t.Fatalf("SelectCandidate with skip failed: %v", err)
	}
	if secondCandidate.Key() == firstCandidate.Key() {
		t.Fatalf("skipped candidate was selected")
	}
}

func TestFrontedMeekCDNScanSpecSkipUsesShuffleOrder(t *testing.T) {

	spec := FrontedMeekCDNScanSpec{
		IPCandidates:   []string{"192.0.2.0/29"},
		SNIServerNames: []string{"one.example.com", "two.example.com"},
	}
	shuffleKey := "client-a"

	firstCandidate, ok, err := spec.SelectCandidateWithShuffleKey(
		0,
		nil,
		shuffleKey)
	if err != nil || !ok {
		t.Fatalf("SelectCandidateWithShuffleKey failed: ok=%t err=%v", ok, err)
	}

	expectedCandidate, ok, err := spec.SelectCandidateWithShuffleKey(
		1,
		nil,
		shuffleKey)
	if err != nil || !ok {
		t.Fatalf("SelectCandidateWithShuffleKey failed: ok=%t err=%v", ok, err)
	}

	selectedCandidate, ok, err := spec.SelectCandidateWithShuffleKey(
		0,
		map[string]struct{}{firstCandidate.Key(): {}},
		shuffleKey)
	if err != nil || !ok {
		t.Fatalf("SelectCandidateWithShuffleKey failed: ok=%t err=%v", ok, err)
	}

	if selectedCandidate.Key() != expectedCandidate.Key() {
		t.Fatalf(
			"selected %s, expected next shuffled candidate %s",
			selectedCandidate.Key(),
			expectedCandidate.Key())
	}
}

func TestFrontedMeekCDNScanSpecShuffleKey(t *testing.T) {

	spec := FrontedMeekCDNScanSpec{
		IPCandidates:   []string{"192.0.2.0/29"},
		SNIServerNames: []string{"one.example.com", "two.example.com"},
	}

	orders := make([][]string, 0, 2)
	for _, shuffleKey := range []string{"client-a", "client-b"} {
		order := make([]string, 0, spec.CandidateCount())
		for i := 0; i < spec.CandidateCount(); i++ {
			candidate, ok, err := spec.SelectCandidateWithShuffleKey(
				i,
				nil,
				shuffleKey)
			if err != nil || !ok {
				t.Fatalf("SelectCandidateWithShuffleKey failed: ok=%t err=%v", ok, err)
			}
			order = append(order, candidate.Key())
		}
		orders = append(orders, order)
	}

	if len(orders[0]) != len(orders[1]) {
		t.Fatalf("unexpected order length mismatch")
	}
	sameOrder := true
	for i := range orders[0] {
		if orders[0][i] != orders[1][i] {
			sameOrder = false
			break
		}
	}
	if sameOrder {
		t.Fatalf("different shuffle keys produced the same candidate order")
	}
}

func TestFrontedMeekDialOverrideSpecsValidation(t *testing.T) {

	testCases := []struct {
		name      string
		overrides FrontedMeekDialOverrideSpecs
	}{
		{
			name: "missing match",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					DialAddresses: []string{"example.com"},
				},
			},
		},
		{
			name: "invalid regex",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					MatchDialAddressRegexes: []string{"["},
					DialAddresses:           []string{"example.com"},
				},
			},
		},
		{
			name: "pins without verify names",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					MatchDialAddressRegexes: []string{"example"},
					DialAddresses:           []string{"example.com"},
					VerifyPins:              []string{"pin"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		err := testCase.overrides.Validate(nil)
		if err == nil {
			t.Fatalf("unexpected success for %s", testCase.name)
		}
	}
}
