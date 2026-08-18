/*
 * Copyright (c) 2021, Psiphon Inc.
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

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"regexp"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
)

// FrontingSpecs is a list of domain fronting specs.
type FrontingSpecs []*FrontingSpec

// FrontingSpec specifies a domain fronting configuration, to be used with
// MeekConn and MeekModePlaintextRoundTrip. In MeekModePlaintextRoundTrip, the
// fronted origin is an arbitrary web server, not a Psiphon server. This
// MeekConn mode requires HTTPS and server certificate validation:
// VerifyServerName is required; VerifyPins is recommended. See also
// psiphon.MeekConfig and psiphon.MeekConn.
//
// FrontingSpec.Addresses supports the functionality of both
// ServerEntry.MeekFrontingAddressesRegex and
// ServerEntry.MeekFrontingAddresses: multiple candidates are supported, and
// each candidate may be a regex, or a static value (with regex syntax).
type FrontingSpec struct {

	// Optional/new fields use omitempty to minimize tactics tag churn.

	FrontingProviderID string
	Transports         protocol.FrontingTransports `json:",omitempty"`
	Addresses          []string
	DisableSNI         bool     `json:",omitempty"`
	SkipVerify         bool     `json:",omitempty"`
	VerifyServerName   string   `json:",omitempty"`
	VerifyPins         []string `json:",omitempty"`
	Host               string
}

// FrontedMeekDialOverrideSpecs is a list of fronted meek outer-dial override
// rules. These rules are applied after the server entry fronting address and
// host are selected and only affect the client-to-front TLS connection.
type FrontedMeekDialOverrideSpecs []*FrontedMeekDialOverride

// FrontedMeekDialOverride conditionally replaces the fronted meek TLS dial
// endpoint and related TLS settings while preserving the meek Host header.
type FrontedMeekDialOverride struct {

	// Optional/new fields use omitempty to minimize tactics tag churn.

	OverrideID string `json:",omitempty"`

	MatchFrontingProviderIDRegexes []string `json:",omitempty"`
	MatchDialAddressRegexes        []string `json:",omitempty"`
	MatchHostHeaderRegexes         []string `json:",omitempty"`

	DialAddresses     []string
	DisableSNI        bool     `json:",omitempty"`
	SNIServerName     string   `json:",omitempty"`
	VerifyServerNames []string `json:",omitempty"`
	VerifyPins        []string `json:",omitempty"`
	ALPNProtocols     []string `json:",omitempty"`
	TLSProfile        string   `json:",omitempty"`
	SkipCertVerify    bool     `json:",omitempty"`
}

// FrontedMeekDialOverrideParameters is the selected override state returned by
// FrontedMeekDialOverrideSpecs.SelectParameters.
type FrontedMeekDialOverrideParameters struct {
	OverrideID        string
	DialAddress       string
	SNIServerName     string
	VerifyServerNames []string
	VerifyPins        []string
	ALPNProtocols     []string
	TLSProfile        string
	SkipCertVerify    bool
}

// FrontedMeekCDNScanSpec configures user-provided CDN edge scan candidates.
// IPCandidates accepts individual IPv4 addresses and IPv4 CIDRs. Each SNI
// server name is paired with each IP candidate, and each IP candidate is also
// tried once with SNI omitted.
type FrontedMeekCDNScanSpec struct {
	IPCandidates   []string
	SNIServerNames []string `json:",omitempty"`
}

// FrontedMeekCDNScanCandidate is a selected edge IP and SNI pair.
type FrontedMeekCDNScanCandidate struct {
	IPAddress     string
	SNIServerName string
}

type frontedMeekCDNScanIPRange struct {
	first uint32
	last  uint32
}

const maxFrontedMeekCDNScanCandidates = uint64(1<<31 - 1)

// SelectParameters selects fronting parameters from the given FrontingSpecs,
// first selecting a spec at random. SelectParameters is similar to
// psiphon.selectFrontingParameters, which operates on server entries.
//
// The return values are:
// - Dial Address (domain or IP address)
// - Transport (e.g., protocol.FRONTING_TRANSPORT_HTTPS)
// - SNI (which may be transformed; unless it is "", which indicates omit SNI)
// - VerifyServerName (see psiphon.CustomTLSConfig)
// - VerifyPins (see psiphon.CustomTLSConfig)
// - Host (Host header value)
func (specs FrontingSpecs) SelectParameters() (
	string, string, string, string, string, []string, string, error) {

	if len(specs) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting spec")
	}

	spec := specs[prng.Intn(len(specs))]

	if len(spec.Addresses) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting address")
	}

	// For backwards compatibility, the transport type defaults
	// to "FRONTED-HTTPS" when the FrontingSpec specifies no transport types.
	transport := protocol.FRONTING_TRANSPORT_HTTPS
	if len(spec.Transports) > 0 {
		transport = spec.Transports[prng.Intn(len(spec.Transports))]
	}

	frontingDialAddr, err := regen.GenerateString(
		spec.Addresses[prng.Intn(len(spec.Addresses))])
	if err != nil {
		return "", "", "", "", "", nil, "", errors.Trace(err)
	}

	SNIServerName := frontingDialAddr
	if spec.DisableSNI || net.ParseIP(frontingDialAddr) != nil {
		SNIServerName = ""
	}

	// When SkipVerify is true, VerifyServerName and VerifyPins must be empty,
	// as checked in Validate. When dialing in any mode, MeekConn will set
	// CustomTLSConfig.SkipVerify to true as long as VerifyServerName is "".
	// So SkipVerify does not need to be explicitly returned.

	return spec.FrontingProviderID,
		transport,
		frontingDialAddr,
		SNIServerName,
		spec.VerifyServerName,
		spec.VerifyPins,
		spec.Host,
		nil
}

// Validate checks that the JSON values are well-formed.
func (specs FrontingSpecs) Validate(allowSkipVerify bool) error {

	// An empty FrontingSpecs is allowed as a tactics setting, but
	// SelectParameters will fail at runtime: code that uses FrontingSpecs must
	// provide some mechanism -- or check for an empty FrontingSpecs -- to
	// enable/disable features that use FrontingSpecs.

	for _, spec := range specs {
		if len(spec.FrontingProviderID) == 0 {
			return errors.TraceNew("empty fronting provider ID")
		}
		err := spec.Transports.Validate()
		if err != nil {
			return errors.Trace(err)
		}
		if len(spec.Addresses) == 0 {
			return errors.TraceNew("missing fronting addresses")
		}
		for _, addr := range spec.Addresses {
			if len(addr) == 0 {
				return errors.TraceNew("empty fronting address")
			}
		}
		if spec.SkipVerify {
			if !allowSkipVerify {
				return errors.TraceNew("invalid skip verify")
			}
			if len(spec.VerifyServerName) != 0 {
				return errors.TraceNew("unexpected verify server name")
			}
			if len(spec.VerifyPins) != 0 {
				return errors.TraceNew("unexpected verify pins")
			}
		} else {
			if len(spec.VerifyServerName) == 0 {
				return errors.TraceNew("empty verify server name")
			}
			// An empty VerifyPins is allowed.
			for _, pin := range spec.VerifyPins {
				if len(pin) == 0 {
					return errors.TraceNew("empty verify pin")
				}
			}
		}
		if len(spec.Host) == 0 {
			return errors.TraceNew("empty fronting host")
		}
	}
	return nil
}

// SelectParameters selects a fronted meek dial override matching the original
// fronting provider, dial addresses, and Host header. Match groups are ANDed;
// regexes within each group are ORed. MatchDialAddressRegexes is matched
// against any of the dialAddresses values.
func (overrides FrontedMeekDialOverrideSpecs) SelectParameters(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string) (*FrontedMeekDialOverrideParameters, bool, error) {

	if len(overrides) == 0 {
		return nil, false, nil
	}

	for _, override := range overrides {
		if override == nil {
			continue
		}
		matches, err := override.matches(frontingProviderID, dialAddresses, hostHeader)
		if err != nil {
			return nil, false, errors.Trace(err)
		}
		if matches {
			if len(override.DialAddresses) == 0 {
				return nil, false, errors.TraceNew("missing fronted meek dial override address")
			}

			selectedDialAddress := override.DialAddresses[prng.Intn(len(override.DialAddresses))]
			if selectedDialAddress == "" {
				return nil, false, errors.TraceNew("empty fronted meek dial override address")
			}

			return makeFrontedMeekDialOverrideParameters(
				override, selectedDialAddress), true, nil
		}
	}

	return nil, false, nil
}

type frontedMeekDialOverrideCandidate struct {
	override    *FrontedMeekDialOverride
	dialAddress string
}

// CandidateCount returns the number of matching override dial candidates.
func (overrides FrontedMeekDialOverrideSpecs) CandidateCount(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string) (int, error) {

	candidates, err := overrides.matchingCandidates(
		frontingProviderID,
		dialAddresses,
		hostHeader)
	if err != nil {
		return 0, errors.Trace(err)
	}
	return len(candidates), nil
}

// SelectCandidateParameters selects from all matching overrides and dial
// addresses in config order. candidateNumber advances through that ordered
// candidate list, wrapping when all candidates have been tried.
func (overrides FrontedMeekDialOverrideSpecs) SelectCandidateParameters(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string,
	candidateNumber int) (*FrontedMeekDialOverrideParameters, bool, error) {

	if candidateNumber < 0 {
		candidateNumber = 0
	}

	candidates, err := overrides.matchingCandidates(
		frontingProviderID,
		dialAddresses,
		hostHeader)
	if err != nil {
		return nil, false, errors.Trace(err)
	}
	if len(candidates) == 0 {
		return nil, false, nil
	}

	selectedCandidate := candidates[candidateNumber%len(candidates)]
	return makeFrontedMeekDialOverrideParameters(
		selectedCandidate.override,
		selectedCandidate.dialAddress), true, nil
}

// SelectCandidateParametersNoWrap selects from all matching overrides and dial
// addresses in config order without wrapping candidateNumber.
func (overrides FrontedMeekDialOverrideSpecs) SelectCandidateParametersNoWrap(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string,
	candidateNumber int) (*FrontedMeekDialOverrideParameters, bool, error) {

	if candidateNumber < 0 {
		candidateNumber = 0
	}

	candidates, err := overrides.matchingCandidates(
		frontingProviderID,
		dialAddresses,
		hostHeader)
	if err != nil {
		return nil, false, errors.Trace(err)
	}
	if len(candidates) == 0 || candidateNumber >= len(candidates) {
		return nil, false, nil
	}

	selectedCandidate := candidates[candidateNumber]
	return makeFrontedMeekDialOverrideParameters(
		selectedCandidate.override,
		selectedCandidate.dialAddress), true, nil
}

func (overrides FrontedMeekDialOverrideSpecs) matchingCandidates(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string) (
	[]frontedMeekDialOverrideCandidate, error) {

	if len(overrides) == 0 {
		return nil, nil
	}

	candidates := make([]frontedMeekDialOverrideCandidate, 0)

	for _, override := range overrides {
		if override == nil {
			continue
		}
		matches, err := override.matches(frontingProviderID, dialAddresses, hostHeader)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if !matches {
			continue
		}
		if len(override.DialAddresses) == 0 {
			return nil, errors.TraceNew("missing fronted meek dial override address")
		}
		for _, selectedDialAddress := range override.DialAddresses {
			if selectedDialAddress == "" {
				return nil, errors.TraceNew("empty fronted meek dial override address")
			}
			candidates = append(candidates, frontedMeekDialOverrideCandidate{
				override:    override,
				dialAddress: selectedDialAddress,
			})
		}
	}

	return candidates, nil
}

func makeFrontedMeekDialOverrideParameters(
	override *FrontedMeekDialOverride,
	selectedDialAddress string) *FrontedMeekDialOverrideParameters {

	SNIServerName := selectedDialAddress
	if override.DisableSNI {
		SNIServerName = ""
	} else if override.SNIServerName != "" {
		SNIServerName = override.SNIServerName
	}

	return &FrontedMeekDialOverrideParameters{
		OverrideID:        override.OverrideID,
		DialAddress:       selectedDialAddress,
		SNIServerName:     SNIServerName,
		VerifyServerNames: copyStrings(override.VerifyServerNames),
		VerifyPins:        copyStrings(override.VerifyPins),
		ALPNProtocols:     copyStrings(override.ALPNProtocols),
		TLSProfile:        override.TLSProfile,
		SkipCertVerify:    override.SkipCertVerify,
	}
}

// IsEmpty returns whether the scan spec has no IP candidates.
func (spec FrontedMeekCDNScanSpec) IsEmpty() bool {
	return len(splitFrontedMeekCDNScanEntries(spec.IPCandidates)) == 0
}

// Validate checks that scan IP and SNI candidates are well-formed.
func (spec FrontedMeekCDNScanSpec) Validate() error {
	_, _, err := spec.normalized()
	return errors.Trace(err)
}

// CandidateCount returns the number of IP/SNI candidate pairs. Large spaces
// are capped at MaxInt32 to keep candidate numbering compatible with int.
func (spec FrontedMeekCDNScanSpec) CandidateCount() int {
	ranges, sniServerNames, err := spec.normalized()
	if err != nil {
		return 0
	}
	count := frontedMeekCDNScanCandidateCount(ranges, sniServerNames)
	if count > maxFrontedMeekCDNScanCandidates {
		return int(maxFrontedMeekCDNScanCandidates)
	}
	return int(count)
}

// SNIServerNameCount returns the number of configured SNI server names.
func (spec FrontedMeekCDNScanSpec) SNIServerNameCount() int {
	_, sniServerNames, err := spec.normalized()
	if err != nil {
		return 0
	}
	return len(sniServerNames)
}

// CacheKey returns a stable digest for the normalized candidate set.
func (spec FrontedMeekCDNScanSpec) CacheKey() string {
	ranges, sniServerNames, err := spec.normalized()
	if err != nil {
		return ""
	}
	hash := sha256.New()
	for _, ipRange := range ranges {
		var data [8]byte
		binary.BigEndian.PutUint32(data[0:4], ipRange.first)
		binary.BigEndian.PutUint32(data[4:8], ipRange.last)
		hash.Write(data[:])
	}
	hash.Write([]byte{0})
	for _, sniServerName := range sniServerNames {
		hash.Write([]byte(strings.ToLower(sniServerName)))
		hash.Write([]byte{0})
	}
	// Empty SNI is an implicit additional variant for every IP candidate.
	hash.Write([]byte{0})
	return hex.EncodeToString(hash.Sum(nil))
}

// SelectCandidate selects an IP/SNI candidate in a deterministic shuffled
// order. skipped contains candidate keys that should be temporarily
// deprioritized; if all probed candidates are skipped, the selected candidate
// is returned anyway so establishment can continue.
func (spec FrontedMeekCDNScanSpec) SelectCandidate(
	candidateNumber int,
	skipped map[string]struct{}) (*FrontedMeekCDNScanCandidate, bool, error) {

	return spec.SelectCandidateWithShuffleKey(candidateNumber, skipped, "")
}

// SelectCandidateWithShuffleKey is equivalent to SelectCandidate, but salts
// the deterministic shuffle with a caller-supplied key so different clients can
// scan the same candidate set in different orders.
func (spec FrontedMeekCDNScanSpec) SelectCandidateWithShuffleKey(
	candidateNumber int,
	skipped map[string]struct{},
	shuffleKey string) (*FrontedMeekCDNScanCandidate, bool, error) {

	ranges, sniServerNames, err := spec.normalized()
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	count := frontedMeekCDNScanCandidateCount(ranges, sniServerNames)
	if count == 0 {
		return nil, false, nil
	}
	if count > maxFrontedMeekCDNScanCandidates {
		count = maxFrontedMeekCDNScanCandidates
	}

	if candidateNumber < 0 {
		candidateNumber = 0
	}

	probeLimit := uint64(len(skipped) + 1)
	if probeLimit > count {
		probeLimit = count
	}
	if probeLimit == 0 {
		probeLimit = 1
	}

	var fallback *FrontedMeekCDNScanCandidate
	for i := uint64(0); i < probeLimit; i++ {
		index := spec.permutedCandidateIndex(
			uint64(candidateNumber)+i,
			count,
			shuffleKey)
		candidate := frontedMeekCDNScanCandidateAt(
			ranges,
			sniServerNames,
			index)
		if fallback == nil {
			fallback = candidate
		}
		if _, ok := skipped[candidate.Key()]; !ok {
			return candidate, true, nil
		}
	}

	return fallback, fallback != nil, nil
}

// Key returns a stable cache key for the candidate.
func (candidate FrontedMeekCDNScanCandidate) Key() string {
	return candidate.IPAddress + "|" + strings.ToLower(candidate.SNIServerName)
}

func (spec FrontedMeekCDNScanSpec) normalized() (
	[]frontedMeekCDNScanIPRange, []string, error) {

	ranges := make([]frontedMeekCDNScanIPRange, 0)
	seenIPCandidates := make(map[string]struct{})

	for _, token := range splitFrontedMeekCDNScanEntries(spec.IPCandidates) {
		ipRange, canonical, err := parseFrontedMeekCDNScanIPCandidate(token)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		if _, ok := seenIPCandidates[canonical]; ok {
			continue
		}
		seenIPCandidates[canonical] = struct{}{}
		ranges = append(ranges, ipRange)
	}

	sniServerNames := make([]string, 0)
	seenSNIServerNames := make(map[string]struct{})
	for _, token := range splitFrontedMeekCDNScanEntries(spec.SNIServerNames) {
		sniServerName := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(token)), ".")
		if !isValidFrontedMeekCDNScanHostname(sniServerName) {
			return nil, nil, errors.Tracef(
				"invalid fronted meek CDN scan SNI server name: %s", token)
		}
		if _, ok := seenSNIServerNames[sniServerName]; ok {
			continue
		}
		seenSNIServerNames[sniServerName] = struct{}{}
		sniServerNames = append(sniServerNames, sniServerName)
	}

	return ranges, sniServerNames, nil
}

func splitFrontedMeekCDNScanEntries(values []string) []string {
	entries := make([]string, 0)
	for _, value := range values {
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
		}) {
			token = strings.TrimSpace(token)
			if token != "" {
				entries = append(entries, token)
			}
		}
	}
	return entries
}

func parseFrontedMeekCDNScanIPCandidate(token string) (
	frontedMeekCDNScanIPRange, string, error) {

	if strings.Contains(token, "/") {
		ip, network, err := net.ParseCIDR(token)
		if err != nil {
			return frontedMeekCDNScanIPRange{}, "", errors.Trace(err)
		}
		ipv4 := ip.To4()
		networkIPv4 := network.IP.To4()
		ones, bits := network.Mask.Size()
		if ipv4 == nil || networkIPv4 == nil || bits != 32 {
			return frontedMeekCDNScanIPRange{}, "", errors.Tracef(
				"invalid fronted meek CDN scan IPv4 CIDR: %s", token)
		}
		size := uint64(1) << uint(bits-ones)
		first := binary.BigEndian.Uint32(networkIPv4)
		last := first + uint32(size-1)
		return frontedMeekCDNScanIPRange{first: first, last: last}, network.String(), nil
	}

	ip := net.ParseIP(token)
	if ip == nil || ip.To4() == nil {
		return frontedMeekCDNScanIPRange{}, "", errors.Tracef(
			"invalid fronted meek CDN scan IPv4 address: %s", token)
	}
	ipValue := binary.BigEndian.Uint32(ip.To4())
	canonical := net.IPv4(ip.To4()[0], ip.To4()[1], ip.To4()[2], ip.To4()[3]).String()
	return frontedMeekCDNScanIPRange{first: ipValue, last: ipValue}, canonical, nil
}

func frontedMeekCDNScanIPRangeCount(ranges []frontedMeekCDNScanIPRange) uint64 {
	var count uint64
	for _, ipRange := range ranges {
		count += uint64(ipRange.last-ipRange.first) + 1
		if count > maxFrontedMeekCDNScanCandidates {
			return maxFrontedMeekCDNScanCandidates
		}
	}
	return count
}

func frontedMeekCDNScanCandidateCount(
	ranges []frontedMeekCDNScanIPRange,
	sniServerNames []string) uint64 {

	ipCount := frontedMeekCDNScanIPRangeCount(ranges)
	if ipCount == 0 {
		return 0
	}

	sniVariantCount := uint64(len(sniServerNames)) + 1
	if ipCount > maxFrontedMeekCDNScanCandidates/sniVariantCount {
		return maxFrontedMeekCDNScanCandidates
	}

	return ipCount * sniVariantCount
}

func (spec FrontedMeekCDNScanSpec) permutedCandidateIndex(
	candidateNumber, count uint64,
	shuffleKey string) uint64 {

	cacheKey := spec.CacheKey()
	seed := sha256.Sum256([]byte(
		"fronted-meek-cdn-scan|" + cacheKey + "|" + shuffleKey))
	offset := binary.BigEndian.Uint64(seed[0:8]) % count
	step := binary.BigEndian.Uint64(seed[8:16]) % count
	if step == 0 {
		step = 1
	}
	for gcdUint64(step, count) != 1 {
		step++
		if step >= count {
			step = 1
		}
	}
	return (offset + (candidateNumber%count)*step) % count
}

func frontedMeekCDNScanCandidateAt(
	ranges []frontedMeekCDNScanIPRange,
	sniServerNames []string,
	index uint64) *FrontedMeekCDNScanCandidate {

	sniCount := uint64(len(sniServerNames)) + 1
	ipIndex := index / sniCount
	sniIndex := index % sniCount

	for _, ipRange := range ranges {
		rangeSize := uint64(ipRange.last-ipRange.first) + 1
		if ipIndex >= rangeSize {
			ipIndex -= rangeSize
			continue
		}
		ipValue := ipRange.first + uint32(ipIndex)
		ipAddress := net.IPv4(
			byte(ipValue>>24),
			byte(ipValue>>16),
			byte(ipValue>>8),
			byte(ipValue)).String()
		sniServerName := ""
		if sniIndex < uint64(len(sniServerNames)) {
			sniServerName = sniServerNames[sniIndex]
		}
		return &FrontedMeekCDNScanCandidate{
			IPAddress:     ipAddress,
			SNIServerName: sniServerName,
		}
	}

	return nil
}

func isValidFrontedMeekCDNScanHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || net.ParseIP(hostname) != nil {
		return false
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 ||
			strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func gcdUint64(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Validate checks that the JSON values are well-formed.
func (overrides FrontedMeekDialOverrideSpecs) Validate(customTLSProfileNames []string) error {

	for _, override := range overrides {
		if override == nil {
			return errors.TraceNew("nil fronted meek dial override")
		}

		if len(override.MatchFrontingProviderIDRegexes) == 0 &&
			len(override.MatchDialAddressRegexes) == 0 &&
			len(override.MatchHostHeaderRegexes) == 0 {
			return errors.TraceNew("missing fronted meek dial override match criteria")
		}

		if err := validateRegexes(override.MatchFrontingProviderIDRegexes); err != nil {
			return errors.Trace(err)
		}
		if err := validateRegexes(override.MatchDialAddressRegexes); err != nil {
			return errors.Trace(err)
		}
		if err := validateRegexes(override.MatchHostHeaderRegexes); err != nil {
			return errors.Trace(err)
		}

		if len(override.DialAddresses) == 0 {
			return errors.TraceNew("missing fronted meek dial override addresses")
		}
		for _, address := range override.DialAddresses {
			if address == "" {
				return errors.TraceNew("empty fronted meek dial override address")
			}
		}

		if override.DisableSNI && override.SNIServerName != "" {
			return errors.TraceNew("unexpected fronted meek dial override SNI")
		}

		for _, verifyServerName := range override.VerifyServerNames {
			if verifyServerName == "" {
				return errors.TraceNew("empty fronted meek dial override verify server name")
			}
		}
		if len(override.VerifyPins) > 0 && len(override.VerifyServerNames) == 0 {
			return errors.TraceNew("fronted meek dial override verify pins require verify server names")
		}
		if override.SkipCertVerify && len(override.VerifyPins) > 0 {
			return errors.TraceNew("fronted meek dial override skip cert verify is incompatible with verify pins")
		}
		for _, pin := range override.VerifyPins {
			if pin == "" {
				return errors.TraceNew("empty fronted meek dial override verify pin")
			}
		}

		for _, protocol := range override.ALPNProtocols {
			if protocol == "" {
				return errors.TraceNew("empty fronted meek dial override ALPN protocol")
			}
		}

		if override.TLSProfile != "" {
			err := protocol.TLSProfiles{override.TLSProfile}.Validate(customTLSProfileNames)
			if err != nil {
				return errors.Trace(err)
			}
		}
	}

	return nil
}

func (override *FrontedMeekDialOverride) matches(
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string) (bool, error) {

	matches, err := matchesRegexes(override.MatchFrontingProviderIDRegexes, frontingProviderID)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	matches, err = matchesRegexesAny(override.MatchDialAddressRegexes, dialAddresses)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	matches, err = matchesRegexes(override.MatchHostHeaderRegexes, hostHeader)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	return true, nil
}

func validateRegexes(regexes []string) error {
	for _, regex := range regexes {
		if regex == "" {
			return errors.TraceNew("empty fronted meek dial override match regex")
		}
		_, err := regexp.Compile(regex)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func matchesRegexes(regexes []string, value string) (bool, error) {
	if len(regexes) == 0 {
		return true, nil
	}
	for _, regex := range regexes {
		matches, err := regexp.MatchString(regex, value)
		if err != nil {
			return false, errors.Trace(err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func matchesRegexesAny(regexes []string, values []string) (bool, error) {
	if len(regexes) == 0 {
		return true, nil
	}
	for _, value := range values {
		matches, err := matchesRegexes(regexes, value)
		if err != nil {
			return false, errors.Trace(err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copiedValues := make([]string, len(values))
	copy(copiedValues, values)
	return copiedValues
}
