package psiphon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	frontedMeekCDNScanCacheKeyPrefix     = "frontedMeekCDNScanCache"
	frontedMeekCDNScanOverrideID         = "cdn-scan"
	frontedMeekCDNScanSuccessTTL         = 7 * 24 * time.Hour
	frontedMeekCDNScanFailureCooldown    = 2 * time.Hour
	frontedMeekCDNScanProgressInterval   = 50
	frontedMeekCDNScanAggressiveFanout   = 8
	frontedMeekCDNScanConservativeFanout = 1
	frontedMeekCDNScanMaxCandidateCount  = int(1<<31 - 1)
)

type frontedMeekCDNScanCandidateSet struct {
	name string
	spec parameters.FrontedMeekCDNScanSpec
}

type frontedMeekCDNScanCacheEntry struct {
	IPAddress            string
	SNIServerName        string
	LastSuccessTimestamp time.Time `json:",omitempty"`
	LastFailureTimestamp time.Time `json:",omitempty"`
	SuccessCount         int       `json:",omitempty"`
	FailureCount         int       `json:",omitempty"`
}

type frontedMeekCDNScanCacheRecord struct {
	Entries     map[string]*frontedMeekCDNScanCacheEntry
	ShuffleSeed string `json:",omitempty"`
}

type frontedMeekCDNScanState struct {
	mutex               sync.Mutex
	datastoreKey        string
	loaded              bool
	entries             map[string]*frontedMeekCDNScanCacheEntry
	shuffleSeed         string
	attempts            int
	lastProgressAttempt int
	exhaustedLogged     bool
}

var frontedMeekCDNScanStates sync.Map

func noticeFrontedMeekCDNScanActive(
	p parameters.ParametersAccessor,
	networkID string,
	workerPoolSize int,
	aggressive bool) {

	candidateSets := makeFrontedMeekCDNScanCandidateSets(p)
	if frontedMeekCDNScanCandidateSetCount(candidateSets) == 0 {
		return
	}
	getFrontedMeekCDNScanState(networkID, candidateSets).resetEstablishment()

	mode := "normal"
	if aggressive {
		mode = "beast"
	}

	NoticeInfo(
		"cdn fronting scan active (mode: %s, workers: %d)",
		mode,
		workerPoolSize)
}

func frontedMeekCDNScanCandidateFanout(
	p parameters.ParametersAccessor,
	aggressive bool) int {

	candidateCount := frontedMeekCDNScanCandidateSetCount(
		makeFrontedMeekCDNScanCandidateSets(p))
	if candidateCount == 0 {
		return 1
	}
	if !aggressive {
		return frontedMeekCDNScanConservativeFanout
	}
	if candidateCount < frontedMeekCDNScanAggressiveFanout {
		return candidateCount
	}
	return frontedMeekCDNScanAggressiveFanout
}

func selectFrontedMeekCDNScanOverride(
	p parameters.ParametersAccessor,
	networkID string,
	frontingProviderID string,
	dialAddresses []string,
	hostHeader string,
	candidateNumber int) (
	*parameters.FrontedMeekDialOverrideParameters,
	*parameters.FrontedMeekCDNScanCandidate,
	string,
	bool,
	error) {

	userCandidateSets := makeFrontedMeekCDNScanUserCandidateSets(p)
	builtInCandidateSets := makeFrontedMeekCDNScanBuiltInCandidateSets(p)
	candidateSets := append(
		append([]frontedMeekCDNScanCandidateSet{}, userCandidateSets...),
		builtInCandidateSets...)

	scanCandidateCount := frontedMeekCDNScanCandidateSetCount(candidateSets)
	userCandidateCount := frontedMeekCDNScanCandidateSetCount(userCandidateSets)
	builtInCandidateCount := frontedMeekCDNScanCandidateSetCount(builtInCandidateSets)

	overrides := p.FrontedMeekDialOverrides(parameters.FrontedMeekDialOverrides)
	overrideCandidateCount, err := overrides.CandidateCount(
		frontingProviderID,
		dialAddresses,
		hostHeader)
	if err != nil {
		return nil, nil, "", false, errors.Trace(err)
	}

	candidateCount := frontedMeekCDNScanSaturatedAdd(
		scanCandidateCount,
		overrideCandidateCount)
	if candidateCount == 0 {
		return nil, nil, "", false, nil
	}
	if scanCandidateCount == 0 {
		override, ok, err := overrides.SelectCandidateParameters(
			frontingProviderID,
			dialAddresses,
			hostHeader,
			candidateNumber)
		return override, nil, "", ok, errors.Trace(err)
	}

	state := getFrontedMeekCDNScanState(networkID, candidateSets)
	preferredCandidates, skippedCandidates, shuffleKey := state.candidateHints()
	if candidateNumber >= len(preferredCandidates)+candidateCount {
		state.recordExhausted()
		return nil, nil, "", false, nil
	}

	var candidate *parameters.FrontedMeekCDNScanCandidate
	if candidateNumber < len(preferredCandidates) {
		selected := preferredCandidates[candidateNumber]
		candidate = &selected
	} else {
		sourceCandidateNumber := candidateNumber - len(preferredCandidates)
		if sourceCandidateNumber < userCandidateCount {
			var ok bool
			candidate, ok, err = selectFrontedMeekCDNScanCandidate(
				userCandidateSets,
				sourceCandidateNumber,
				skippedCandidates,
				shuffleKey)
			if err != nil {
				return nil, nil, "", false, errors.Trace(err)
			}
			if !ok {
				return nil, nil, "", false, nil
			}
		} else {
			sourceCandidateNumber -= userCandidateCount
			if sourceCandidateNumber < overrideCandidateCount {
				override, ok, err := overrides.SelectCandidateParametersNoWrap(
					frontingProviderID,
					dialAddresses,
					hostHeader,
					sourceCandidateNumber)
				if err != nil {
					return nil, nil, "", false, errors.Trace(err)
				}
				return override, nil, "", ok, nil
			}

			sourceCandidateNumber -= overrideCandidateCount
			if sourceCandidateNumber >= builtInCandidateCount {
				return nil, nil, "", false, nil
			}

			var ok bool
			candidate, ok, err = selectFrontedMeekCDNScanCandidate(
				builtInCandidateSets,
				sourceCandidateNumber,
				skippedCandidates,
				shuffleKey)
			if err != nil {
				return nil, nil, "", false, errors.Trace(err)
			}
			if !ok {
				return nil, nil, "", false, nil
			}
		}
	}

	state.recordAttempt()

	return &parameters.FrontedMeekDialOverrideParameters{
			OverrideID:        frontedMeekCDNScanOverrideID,
			DialAddress:       candidate.IPAddress,
			SNIServerName:     candidate.SNIServerName,
			VerifyServerNames: makeFrontedMeekCDNScanVerifyServerNames(*candidate),
			ALPNProtocols:     []string{"http/1.1"},
			TLSProfile:        "Chrome-83",
		},
		candidate,
		state.datastoreKey,
		true,
		nil
}

func recordFrontedMeekCDNScanResult(dialParams *DialParameters, success bool) {
	if dialParams == nil ||
		!dialParams.FrontedMeekCDNScanCandidate ||
		dialParams.frontedMeekCDNScanStateKey == "" {
		return
	}

	value, ok := frontedMeekCDNScanStates.Load(dialParams.frontedMeekCDNScanStateKey)
	if !ok {
		return
	}
	state := value.(*frontedMeekCDNScanState)
	state.recordResult(dialParams.frontedMeekCDNScanSelectedCandidate, success)
}

func isFrontedMeekCDNScanDialParams(dialParams *DialParameters) bool {
	return dialParams != nil &&
		(dialParams.FrontedMeekCDNScanCandidate ||
			dialParams.MeekFrontingDialOverrideID == frontedMeekCDNScanOverrideID)
}

func frontedMeekCDNScanCandidateFromDialParams(
	dialParams *DialParameters) parameters.FrontedMeekCDNScanCandidate {

	if dialParams == nil {
		return parameters.FrontedMeekCDNScanCandidate{}
	}
	candidate := parameters.FrontedMeekCDNScanCandidate{
		IPAddress:     dialParams.MeekFrontingDialAddress,
		SNIServerName: dialParams.MeekSNIServerName,
	}
	if candidate.IPAddress == "" && dialParams.FrontedMeekCDNScanCandidate {
		return dialParams.frontedMeekCDNScanSelectedCandidate
	}
	return candidate
}

func noticeFrontedMeekCDNScanConnected(dialParams *DialParameters) {

	if dialParams == nil ||
		(!isFrontedMeekCDNScanDialParams(dialParams) &&
			!protocol.TunnelProtocolUsesFrontedMeekCDN(dialParams.TunnelProtocol)) {
		return
	}
	noticeFrontedMeekCDNScanFound(
		frontedMeekCDNScanCandidateFromDialParams(dialParams))
}

func makeFrontedMeekCDNScanCandidateSets(
	p parameters.ParametersAccessor) []frontedMeekCDNScanCandidateSet {

	candidateSets := makeFrontedMeekCDNScanUserCandidateSets(p)
	candidateSets = append(candidateSets, makeFrontedMeekCDNScanBuiltInCandidateSets(p)...)

	return candidateSets
}

func makeFrontedMeekCDNScanUserCandidateSets(
	p parameters.ParametersAccessor) []frontedMeekCDNScanCandidateSet {

	candidateSets := make([]frontedMeekCDNScanCandidateSet, 0, 1)
	userSpec := p.FrontedMeekCDNScanSpec(parameters.FrontedMeekCDNScanSpecParameter)
	if userSpec.CandidateCount() > 0 {
		candidateSets = append(candidateSets, frontedMeekCDNScanCandidateSet{
			name: "user",
			spec: userSpec,
		})
	}

	return candidateSets
}

func makeFrontedMeekCDNScanBuiltInCandidateSets(
	p parameters.ParametersAccessor) []frontedMeekCDNScanCandidateSet {

	if !p.Bool(parameters.FrontedMeekCDNScanUseBuiltInSpec) {
		return nil
	}

	selected := p.Strings(parameters.FrontedMeekCDNScanBuiltInSets)
	if len(selected) == 0 {
		return frontedMeekCDNScanBuiltInCandidateSets
	}

	candidateSets := make([]frontedMeekCDNScanCandidateSet, 0, len(selected))
	for _, name := range selected {
		for _, candidateSet := range frontedMeekCDNScanBuiltInCandidateSets {
			if frontedMeekCDNScanBuiltInSetNameMatches(name, candidateSet.name) {
				candidateSets = append(candidateSets, candidateSet)
				break
			}
		}
	}
	return candidateSets
}

func frontedMeekCDNScanBuiltInSetNameMatches(name, candidateSetName string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	return name == candidateSetName ||
		name == strings.TrimPrefix(candidateSetName, "built-in-")
}

func frontedMeekCDNScanCandidateSetCount(
	candidateSets []frontedMeekCDNScanCandidateSet) int {

	total := 0
	for _, candidateSet := range candidateSets {
		count := candidateSet.spec.CandidateCount()
		if count <= 0 {
			continue
		}
		if total > frontedMeekCDNScanMaxCandidateCount-count {
			return frontedMeekCDNScanMaxCandidateCount
		}
		total += count
	}
	return total
}

func frontedMeekCDNScanSaturatedAdd(a, b int) int {
	if a > frontedMeekCDNScanMaxCandidateCount-b {
		return frontedMeekCDNScanMaxCandidateCount
	}
	return a + b
}

func frontedMeekCDNScanCandidateSetsCacheKey(
	candidateSets []frontedMeekCDNScanCandidateSet) string {

	hash := sha256.New()
	for _, candidateSet := range candidateSets {
		if candidateSet.spec.CandidateCount() == 0 {
			continue
		}
		hash.Write([]byte(candidateSet.name))
		hash.Write([]byte{0})
		hash.Write([]byte(candidateSet.spec.CacheKey()))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func selectFrontedMeekCDNScanCandidate(
	candidateSets []frontedMeekCDNScanCandidateSet,
	candidateNumber int,
	skippedCandidates map[string]struct{},
	shuffleKey string) (*parameters.FrontedMeekCDNScanCandidate, bool, error) {

	if candidateNumber < 0 {
		candidateNumber = 0
	}

	for _, candidateSet := range candidateSets {
		count := candidateSet.spec.CandidateCount()
		if count <= 0 {
			continue
		}
		if candidateNumber >= count {
			candidateNumber -= count
			continue
		}
		candidate, ok, err := candidateSet.spec.SelectCandidateWithShuffleKey(
			candidateNumber,
			skippedCandidates,
			shuffleKey)
		return candidate, ok, errors.Trace(err)
	}

	return nil, false, nil
}

func getFrontedMeekCDNScanState(
	networkID string,
	candidateSets []frontedMeekCDNScanCandidateSet) *frontedMeekCDNScanState {

	datastoreKey := strings.Join([]string{
		frontedMeekCDNScanCacheKeyPrefix,
		networkID,
		frontedMeekCDNScanCandidateSetsCacheKey(candidateSets),
	}, ":")

	value, _ := frontedMeekCDNScanStates.LoadOrStore(
		datastoreKey,
		&frontedMeekCDNScanState{
			datastoreKey: datastoreKey,
			entries:      make(map[string]*frontedMeekCDNScanCacheEntry),
		})
	state := value.(*frontedMeekCDNScanState)
	state.load()
	return state
}

func (state *frontedMeekCDNScanState) load() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.loaded {
		return
	}
	state.loaded = true
	defer func() {
		if state.shuffleSeed == "" {
			state.shuffleSeed = prng.HexString(16)
		}
	}()

	jsonCache, err := GetKeyValue(state.datastoreKey)
	if err != nil || jsonCache == "" {
		return
	}

	var record frontedMeekCDNScanCacheRecord
	err = json.Unmarshal([]byte(jsonCache), &record)
	if err != nil || record.Entries == nil {
		return
	}

	state.entries = record.Entries
	state.shuffleSeed = record.ShuffleSeed
}

func (state *frontedMeekCDNScanState) resetEstablishment() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.attempts = 0
	state.lastProgressAttempt = 0
	state.exhaustedLogged = false
}

func (state *frontedMeekCDNScanState) candidateHints() (
	[]parameters.FrontedMeekCDNScanCandidate,
	map[string]struct{},
	string) {

	now := time.Now()
	preferredCandidates := make([]*frontedMeekCDNScanCacheEntry, 0)
	skippedCandidates := make(map[string]struct{})

	state.mutex.Lock()
	defer state.mutex.Unlock()
	shuffleKey := state.shuffleSeed

	for key, entry := range state.entries {
		failureIsCurrent := !entry.LastFailureTimestamp.IsZero() &&
			entry.LastFailureTimestamp.After(entry.LastSuccessTimestamp)
		if failureIsCurrent &&
			now.Sub(entry.LastFailureTimestamp) < frontedMeekCDNScanFailureCooldown {
			skippedCandidates[key] = struct{}{}
			continue
		}
		if !entry.LastSuccessTimestamp.IsZero() &&
			now.Sub(entry.LastSuccessTimestamp) < frontedMeekCDNScanSuccessTTL &&
			!failureIsCurrent {
			preferredCandidates = append(preferredCandidates, entry)
		}
	}

	sort.Slice(preferredCandidates, func(i, j int) bool {
		if preferredCandidates[i].LastSuccessTimestamp.Equal(
			preferredCandidates[j].LastSuccessTimestamp) {
			return preferredCandidates[i].SuccessCount > preferredCandidates[j].SuccessCount
		}
		return preferredCandidates[i].LastSuccessTimestamp.After(
			preferredCandidates[j].LastSuccessTimestamp)
	})

	candidates := make([]parameters.FrontedMeekCDNScanCandidate, 0, len(preferredCandidates))
	for _, entry := range preferredCandidates {
		candidates = append(candidates, parameters.FrontedMeekCDNScanCandidate{
			IPAddress:     entry.IPAddress,
			SNIServerName: entry.SNIServerName,
		})
	}

	return candidates, skippedCandidates, shuffleKey
}

func (state *frontedMeekCDNScanState) recordAttempt() {

	state.mutex.Lock()
	state.attempts += 1
	attempts := state.attempts
	shouldLog := attempts == 1 ||
		attempts-state.lastProgressAttempt >= frontedMeekCDNScanProgressInterval
	if shouldLog {
		state.lastProgressAttempt = attempts
	}
	working := state.workingCountLocked()
	state.mutex.Unlock()

	if shouldLog {
		NoticeInfo(
			"cdn fronting scan progress (attempts: %d, working: %d)",
			attempts,
			working)
	}
}

func (state *frontedMeekCDNScanState) recordExhausted() {

	state.mutex.Lock()
	if state.exhaustedLogged {
		state.mutex.Unlock()
		return
	}
	state.exhaustedLogged = true
	attempts := state.attempts
	working := state.workingCountLocked()
	state.mutex.Unlock()

	NoticeInfo(
		"cdn fronting scan exhausted (attempts: %d, working: %d)",
		attempts,
		working)
}

func (state *frontedMeekCDNScanState) recordResult(
	candidate parameters.FrontedMeekCDNScanCandidate,
	success bool) {

	now := time.Now()
	key := candidate.Key()

	state.mutex.Lock()
	entry := state.entries[key]
	if entry == nil {
		entry = &frontedMeekCDNScanCacheEntry{
			IPAddress:     candidate.IPAddress,
			SNIServerName: candidate.SNIServerName,
		}
		state.entries[key] = entry
	}

	if success {
		entry.LastSuccessTimestamp = now
		entry.SuccessCount += 1
	} else {
		entry.LastFailureTimestamp = now
		entry.FailureCount += 1
	}
	jsonCache := state.marshalLocked()
	state.mutex.Unlock()

	if jsonCache != nil {
		_ = SetKeyValue(state.datastoreKey, string(jsonCache))
	}
}

func noticeFrontedMeekCDNScanFound(candidate parameters.FrontedMeekCDNScanCandidate) {

	if candidate.IPAddress == "" {
		return
	}
	sniServerName := candidate.SNIServerName
	if sniServerName == "" {
		sniServerName = "none"
	}
	NoticeInfo(
		"cdn fronting scan found (ip: %s, sni: %s)",
		common.EscapeRedactIPAddressString(candidate.IPAddress),
		sniServerName)
}

func (state *frontedMeekCDNScanState) marshalLocked() []byte {
	entries := make(map[string]*frontedMeekCDNScanCacheEntry, len(state.entries))
	for key, entry := range state.entries {
		copyEntry := *entry
		entries[key] = &copyEntry
	}
	record := &frontedMeekCDNScanCacheRecord{
		Entries:     entries,
		ShuffleSeed: state.shuffleSeed,
	}
	jsonCache, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	return jsonCache
}

func (state *frontedMeekCDNScanState) workingCountLocked() int {
	now := time.Now()
	count := 0
	for _, entry := range state.entries {
		if !entry.LastSuccessTimestamp.IsZero() &&
			now.Sub(entry.LastSuccessTimestamp) < frontedMeekCDNScanSuccessTTL &&
			(entry.LastFailureTimestamp.IsZero() ||
				entry.LastSuccessTimestamp.After(entry.LastFailureTimestamp)) {
			count += 1
		}
	}
	return count
}

func makeFrontedMeekCDNScanVerifyServerNames(
	candidate parameters.FrontedMeekCDNScanCandidate) []string {

	verifyServerNames := make([]string, 0, 8)
	seen := make(map[string]struct{})

	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		verifyServerNames = append(verifyServerNames, value)
	}

	add(candidate.SNIServerName)
	add(candidate.IPAddress)
	add("a248.e.akamai.net")
	add("a.akamaized.net")
	add("a.akamaized-staging.net")
	add("a.akamaihd.net")
	add("a.akamaihd-staging.net")
	add("www.akamai.com")

	return verifyServerNames
}
