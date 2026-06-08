# P2 Feature Implementation Layer - Parallel Execution Plan

## Context

Rewriting Xray-core (Go) to Rust. P0+P1+P2 base layers complete. Now implementing 17 P2 feature tasks across 4 crates. Each task 1:1 replicates Go source with Rust idioms. All stub files exist as 1-line comments.

Key constraints: Buffer has no bytes_mut(), cfb-mode 0.9 API, Address API, workspace edition=2024 MSRV=1.85.

## Task Dependency Graph

| Task | ID | Depends On | Reason |
|------|----|-----------|--------|
| 1. Authenticator | fhh | None | Foundation for crypto chain |
| 2. MatcherGroup | 4lj | None | Foundation for geodata matching |
| 3. IP Matcher | if5 | None | Independent IP matching logic |
| 4. GeoData Loader | n17 | None | Independent file loading logic |
| 5. Session+XUDP | 3h5 | None | Independent mux session logic |
| 6. Frame Reader | 3ue | None | Simple reader, no deps |
| 7. Frame Writer | wqn | None | Simple writer, no deps |
| 8. CryptionReader/Writer | 383 | None | Stream cipher XOR, no deps |
| 9. XUDP Extension | dsi | None | Re-export/integration only |
| 10. Chunk Codec | da8 | Task 1 (fhh) | AEADChunkSizeParser uses AEADAuthenticator |
| 11. ValueMatcher/IndexMatcher | 3oc | Task 2 (4lj) | Uses MatcherGroup implementations |
| 12. Domain/IP Registry | 14h | Task 2+3 | Uses MatcherGroup + IPMatcher |
| 13. AuthenticationReader | 7ua | Task 1+10 | Uses Authenticator + ChunkSizeParser |
| 14. AuthenticationWriter | 8rt | Task 1+10 | Uses Authenticator + ChunkSizeParser |
| 15. Rule Parser | 3ki | Task 4+12 | Uses Loader + Registry |
| 16. Client Worker | 8t4 | Task 5+6+7 | Uses Session + Reader + Writer |
| 17. Server Dispatcher | bc0 | Task 5+6+7 | Uses Session + Reader + Writer |
| 18. Mux Integration Test | 6mq | All above | End-to-end validation |

## Parallel Execution Graph

Wave 1 (9 tasks, no dependencies):
  Task 1: fhh - Authenticator (xray-crypto)
  Task 2: 4lj - MatcherGroup (xray-geodata)
  Task 3: if5 - IP Matcher (xray-geodata)
  Task 4: n17 - GeoData Loader (xray-geodata)
  Task 5: 3h5 - Session+XUDP (xray-mux)
  Task 6: 3ue - Frame Reader (xray-mux)
  Task 7: wqn - Frame Writer (xray-mux)
  Task 8: 383 - CryptionReader/Writer (xray-crypto)
  Task 9: dsi - XUDP Extension (xray-xudp)

Wave 2 (3 tasks, after Wave 1):
  Task 10: da8 - Chunk Codec (depends: fhh)
  Task 11: 3oc - ValueMatcher/IndexMatcher (depends: 4lj)
  Task 12: 14h - Domain/IP Registry (depends: 4lj+if5)

Wave 3 (2 tasks, after Wave 2):
  Task 13: 7ua - AuthenticationReader (depends: fhh+da8)
  Task 14: 8rt - AuthenticationWriter (depends: fhh+da8)

Wave 4 (3 tasks, after Wave 3):
  Task 15: 3ki - Rule Parser (depends: n17+14h)
  Task 16: 8t4 - Client Worker (depends: 3h5+3ue+wqn)
  Task 17: bc0 - Server Dispatcher (depends: 3h5+3ue+wqn)

Wave 5 (1 task, after all above):
  Task 18: 6mq - Mux Integration Test

Critical Path: fhh -> da8 -> 7ua/8rt
Secondary Path: 4lj -> 3oc/14h -> 3ki
Tertiary Path: 3h5+3ue+wqn -> 8t4/bc0
Estimated Parallel Speedup: ~60%

## Tasks

### Task 1: fhh - P2-1.4 Authenticator

File: crates/xray-crypto/src/authenticator.rs
Go source: common/protocol/cryption/auth.go (Authenticator+AEADAuthenticator+BytesGenerator only)
Description: Implement Authenticator trait, AEADAuthenticator, BytesGenerator types.

Delegation Recommendation:
- Category: deep - Complex trait design with crypto integration
- Skills: [tdd-workflow]

Skills Evaluation:
- INCLUDED tdd-workflow: Crypto code must be test-first
- OMITTED code-refactoring: New code
- OMITTED security-vulnerability-detection: Not an audit task

Depends On: None
Blocks: Task 10 (da8), Task 13 (7ua), Task 14 (8rt)

Implementation Steps:
1. Write failing tests for BytesGenerator types: generate_empty_bytes, generate_static_bytes, generate_increasing_nonce (big-endian increment), generate_aead_nonce_with_size (0xFF prefix + increasing)
2. Implement BytesGenerator as Box<dyn Fn() -> Vec<u8> + Send + Sync> with 4 constructor functions. generate_increasing_nonce uses Arc<Mutex<Vec<u8>>> for interior mutability.
3. Write failing tests for Authenticator trait: nonce_size, overhead, open (decrypt), seal (encrypt)
4. Implement Authenticator trait with methods: nonce_size(), overhead(), open(dst, cipher_text), seal(dst, plain_text)
5. Implement AEADAuthenticator struct: cipher (Box<dyn AeadCipher>), nonce_generator (BytesGenerator), additional_data_generator (BytesGenerator). open() gets nonce, validates size>=overhead, gets optional AD, calls cipher.open(). seal() same pattern.
6. Add re-exports in lib.rs
7. Run cargo test -p xray-crypto

Acceptance Criteria:
- All 4 BytesGenerator types produce correct output
- AEADAuthenticator roundtrip with AES-128-GCM and ChaCha20-Poly1305
- cargo test -p xray-crypto passes

---

### Task 2: 4lj - P2-2.3 MatcherGroup Implementations

File: crates/xray-geodata/src/matcher/matchers.rs (extend 506-line file)
Go source: common/strmatcher/matchergroup_*.go (6 files)
Description: Implement all 6 MatcherGroup types.

Delegation Recommendation:
- Category: deep - Complex algorithms (AC automaton, MPH, Rabin-Karp)
- Skills: [tdd-workflow]

Skills Evaluation:
- INCLUDED tdd-workflow: Complex algorithms need test-driven verification
- OMITTED code-refactoring: New code
- OMITTED performance-optimizer: Implementing from spec

Depends On: None
Blocks: Task 11 (3oc), Task 12 (14h)

Implementation Steps (TDD each):
1. FullMatcherGroup: HashMap<String, Vec<u32>>, add+match_pattern
2. DomainMatcherGroup: Trie with TrieNode{values, children HashMap}, split-by-dot right-to-left insert/match
3. SimpleMatcherGroup: Vec<MatcherEntry>, linear scan
4. SubstrMatcherGroup: sorted patterns+values, substring matching
5. ACAutomatonMatcherGroup: LDH charset (39 chars: a-z,0-9,-,.), AcNode with next[39]+fail+match_values, BFS fail edges with path compression
6. MphMatcherGroup: PrimeRK=16777619, rolling_hash, MphRuleInfo{rolling_hash, matchers[2]}, Hash-Displace-Compress build, level0->seed->level1->ruleIdx lookup
7. Update matcher/mod.rs with re-exports
8. Run cargo test -p xray-geodata

Acceptance Criteria:
- All 6 MatcherGroup types pass tests
- DomainMatcherGroup matches subdomains correctly
- AC automaton handles LDH charset
- MPH produces same results as Go
- cargo test -p xray-geodata passes

---

### Task 3: if5 - P2-2.5 IP Matcher

File: crates/xray-geodata/src/matcher/ip.rs
Go source: common/geodata/ip_matcher.go (~1023 lines)
Description: Implement IPMatcher trait, IPSet, HeuristicIPMatcher, HeuristicMultiIPMatcher, GeneralMultiIPMatcher, IPSetFactory.

Delegation Recommendation:
- Category: deep - IP matching with heuristic bucketing and caching
- Skills: [tdd-workflow]

Depends On: None
Blocks: Task 12 (14h)

Implementation Steps (TDD each):
1. IPSet: ipv4_set + ipv6_set (ipnet or custom prefix trie), max4/max6 u8, contains()
2. IPMatcher trait: match_ip, any_match, matches, filter_ips, toggle_reverse, set_reverse
3. HeuristicIPMatcher: IPSet + AtomicBool reverse, prefix_key_from_ip (/24 IPv4, /64 IPv6)
4. HeuristicMultiIPMatcher: Vec<Box<dyn IPMatcher>>, shared bucket optimization
5. GeneralMultiIPMatcher: Vec<Box<dyn IPMatcher>>, sequential delegation
6. IPSetFactory: Mutex<HashMap<String, Weak<IPSet>>>, get_or_create_from_geoip_rules, create_from_cidrs
7. Add re-exports in matcher/mod.rs
8. Run cargo test -p xray-geodata

Acceptance Criteria:
- IPSet contains/excludes correctly from CIDR ranges
- /24/64 bucketing works
- IPSetFactory Weak caching works
- cargo test -p xray-geodata passes

---

### Task 4: n17 - P2-2.7 GeoData Loader

File: crates/xray-geodata/src/loader.rs
Go source: common/geodata/geodat_loader.go (~207 lines)
Description: Streaming protobuf dat file loader.

Delegation Recommendation:
- Category: deep - Streaming protobuf parser
- Skills: [tdd-workflow]

Depends On: None
Blocks: Task 15 (3ki)

Implementation Steps:
1. TDD decode_varint: single-byte, multi-byte, edge cases
2. TDD find(): stream parser reading tag+varint+prefix, match code, read body
3. TDD AttributeMatcher: HasAttrMatcher + AllAttrsMatcher
4. Public API: check_file, load_file, load_ip, load_site, load_site_with_attrs
5. Add re-exports in lib.rs
6. Run cargo test -p xray-geodata

Acceptance Criteria:
- decode_varint handles all protobuf varint formats
- find streams and locates entries in dat files
- load_ip/load_site parse protobuf correctly
- cargo test -p xray-geodata passes

---

### Task 5: 3h5 - P2-3.2 Session Management + XUDP Integration

File: crates/xray-mux/src/session.rs
Go source: common/mux/session.go (~252 lines)
Description: SessionManager, Session, XUDP, XUDPManager.

Delegation Recommendation:
- Category: deep - Concurrent state with RwLock, async cleanup
- Skills: [tdd-workflow]

Depends On: None
Blocks: Task 16 (8t4), Task 17 (bc0)

Implementation Steps:
1. TDD SessionManager: RwLock + HashMap<u16,Session> + count u16 + closed bool; allocate/add/remove/get/close_if_no_session_and_idle/close
2. TDD Session: input/output channels, parent Weak<SessionManager>, ID u16, transfer_type, closed/done flags, close()
3. XUDP struct: GlobalID [u8;8], Status (Initializing=0, Active=1, Expiring=2), Expire Instant, Mux bool; interrupt()
4. XUDPManager: global Mutex + Map<u16, XUDP>, spawn cleanup task every 60s removing expired entries
5. Add re-exports in lib.rs
6. Run cargo test -p xray-mux

Acceptance Criteria:
- SessionManager allocates unique IDs correctly
- Sessions close and cleanup properly
- XUDPManager expires entries after timeout
- cargo test -p xray-mux passes

---

### Task 6: 3ue - P2-3.3 Frame Data Reader

File: crates/xray-mux/src/worker.rs (part)
Go source: common/mux/reader.go (~59 lines)
Description: PacketReader + StreamReader.

Delegation Recommendation:
- Category: quick - Simple reader implementations (~59 lines Go)
- Skills: [tdd-workflow]

Depends On: None
Blocks: Task 16 (8t4), Task 17 (bc0)

Implementation Steps:
1. TDD PacketReader: read 2-byte BE size then payload bytes, handle EOF
2. TDD StreamReader: ChunkStreamReaderWithChunkCount using PlainChunkSizeParser, reader, chunk_count=1
3. Add to worker.rs module
4. Run cargo test -p xray-mux

Acceptance Criteria:
- PacketReader reads 2-byte size + payload correctly
- StreamReader uses chunk protocol correctly
- cargo test -p xray-mux passes

---

### Task 7: wqn - P2-3.4 Frame Data Writer

File: crates/xray-mux/src/worker.rs (part)
Go source: common/mux/writer.go (~136 lines)
Description: Writer struct with WriteMultiBuffer + Close.

Delegation Recommendation:
- Category: deep - Multi-buffer write with stream/packet modes
- Skills: [tdd-workflow]

Depends On: None
Blocks: Task 16 (8t4), Task 17 (bc0)

Implementation Steps:
1. TDD Writer struct: dest, writer, id u16, followup bool, has_error bool, transfer_type, global_id [u8;8], inbound
2. Implement getNextFrameMeta: first call -> SessionStatusNew, subsequent -> SessionStatusKeep
3. TDD writeMetaOnly: write frame with metadata only
4. TDD writeData/writeMetaWithFrame: write frame metadata + data
5. TDD WriteMultiBuffer: empty->metaOnly; stream->8KB chunks with metadata; packet->individual buffers
6. TDD Close: SessionStatusEnd frame, hasError -> OptionError
7. Run cargo test -p xray-mux

Acceptance Criteria:
- Writer handles stream mode (8KB chunking)
- Writer handles packet mode (individual buffers)
- Close writes end frame with optional error
- cargo test -p xray-mux passes

---

### Task 8: 383 - P2-1.8 CryptionReader/Writer

File: crates/xray-crypto/src/ (new file cryption_io.rs or extend lib.rs)
Go source: common/protocol/cryption/io.go (~64 lines)
Description: Stream cipher XOR encrypt/decrypt wrappers.

Delegation Recommendation:
- Category: quick - Simple XOR stream cipher wrappers (~64 lines Go)
- Skills: [tdd-workflow]

Depends On: None
Blocks: None directly

Implementation Steps:
1. TDD CryptionReader: stream cipher + reader, Read decrypts via XOR stream
2. TDD CryptionWriter: stream cipher + writer, Write encrypts via XOR stream then writes
3. TDD CryptionWriter WriteMultiBuffer: encrypt all buffers then delegate
4. Add module to lib.rs exports
5. Run cargo test -p xray-crypto

Acceptance Criteria:
- CryptionReader decrypts stream cipher output correctly
- CryptionWriter encrypts and writes correctly
- WriteMultiBuffer handles multiple buffers
- cargo test -p xray-crypto passes

---

### Task 9: dsi - P2-4.3 XUDP Extension Integration

File: crates/xray-xudp/src/extension.rs
Go source: packet.rs (existing implementation, extension.rs likely re-export/small integration)
Description: XUDP extension integration code.

Delegation Recommendation:
- Category: quick - Likely re-export or small integration code
- Skills: []

Depends On: None
Blocks: None directly

Implementation Steps:
1. Review Go source for what extension.rs should contain
2. Implement re-exports from lib.rs and packet.rs
3. Add any small integration code needed
4. Run cargo test -p xray-xudp

Acceptance Criteria:
- extension.rs properly re-exports XUDP types
- cargo test -p xray-xudp passes

---

### Task 10: da8 - P2-1.5 Chunk Size Codec

File: crates/xray-crypto/src/chunk.rs
Go source: common/protocol/cryption/chunk.go (~160 lines)
Description: ChunkSizeDecoder/Encoder, PlainChunkSizeParser, AEADChunkSizeParser, ChunkStreamReader/Writer.

Delegation Recommendation:
- Category: deep - AEAD-encrypted chunk size encoding requires crypto integration
- Skills: [tdd-workflow]

Depends On: Task 1 (fhh - Authenticator)
Blocks: Task 13 (7ua), Task 14 (8rt)

Implementation Steps:
1. TDD ChunkSizeDecoder trait: size_bytes() -> usize, decode(data) -> Result<u16>
2. TDD ChunkSizeEncoder trait: size_bytes() -> usize, encode(size, data) -> Result<Vec<u8>>
3. TDD PaddingLengthGenerator trait: max_padding_len() -> u16, next_padding_len() -> u16
4. TDD PlainChunkSizeParser: 2-byte BE encode/decode, size_bytes=2
5. TDD AEADChunkSizeParser: uses AEADAuthenticator, size_bytes=2+overhead, Encode=size-overhead then Seal, Decode=Open then add overhead back
6. TDD ChunkStreamReader: size_decoder + reader + left_over tracking, read_size + ReadMultiBuffer
7. TDD ChunkStreamWriter: size_encoder + writer, WriteMultiBuffer splits into 8KB chunks with size prefix
8. Add re-exports in lib.rs
9. Run cargo test -p xray-crypto

Acceptance Criteria:
- PlainChunkSizeParser 2-byte BE roundtrip
- AEADChunkSizeParser encrypt/decrypt size roundtrip
- ChunkStreamReader reads chunked data correctly
- ChunkStreamWriter writes chunked data correctly
- cargo test -p xray-crypto passes

### Task 11: 3oc - P2-2.4 ValueMatcher/IndexMatcher

File: crates/xray-geodata/src/matcher/matchers.rs (extend) + matcher/mod.rs
Go source: common/strmatcher/indexmatcher_linear.go, indexmatcher_mph.go, valuematcher_linear.go, valuematcher_mph.go
Description: LinearIndexMatcher, MphIndexMatcher, LinearValueMatcher, MphValueMatcher, LinearAnyMatcher, MatcherSet variants.

Delegation Recommendation:
- Category: deep - Matcher composition patterns, delegates to sub-groups
- Skills: [tdd-workflow]

Depends On: Task 2 (4lj - MatcherGroup implementations)
Blocks: Task 12 (14h)

Implementation Steps:
1. TDD LinearIndexMatcher: count + full + domain + substr + regex sub-groups, delegates Add/Build/Match/MatchAny
2. TDD MphIndexMatcher: count + mph + ac + regex, delegates to mph+ac+regex
3. TDD LinearValueMatcher: full + domain + substr + regex, delegates Add/Build/Match/MatchAny
4. TDD MphValueMatcher: mph + ac + regex, delegates
5. TDD LinearAnyMatcher: linear scan for any match
6. MatcherSet variants: CompositeMatches, CompositeMatchesReverse
7. Update matcher/mod.rs with new trait definitions (IndexMatcher, ValueMatcher, AnyMatcher) and re-exports
8. Run cargo test -p xray-geodata

Acceptance Criteria:
- LinearIndexMatcher delegates correctly to sub-groups
- MphIndexMatcher uses mph+ac+regex
- ValueMatcher variants return correct values
- LinearAnyMatcher finds any match
- cargo test -p xray-geodata passes

---

### Task 12: 14h - P2-2.6 Domain/IP Registry

File: crates/xray-geodata/src/matcher/domain.rs + matcher/ip.rs (extend)
Go source: common/geodata/domain_matcher.go + domain_registry.go + ip_registry.go
Description: DomainMatcher trait, DomainMatcherFactory, MphDomainMatcherFactory, CompactDomainMatcherFactory, DomainRegistry, IPRegistry, DynamicMatchers.

Delegation Recommendation:
- Category: deep - Registry with caching, atomic dynamic matchers
- Skills: [tdd-workflow]

Depends On: Task 2 (4lj - MatcherGroup) + Task 3 (if5 - IP Matcher)
Blocks: Task 15 (3ki - Rule Parser)

Implementation Steps:
1. TDD DomainMatcher trait: match(input) -> Vec<u32>, match_any(input) -> bool
2. TDD DomainMatcherFactory trait: build_matcher(rules) -> Box<dyn DomainMatcher>
3. TDD MphDomainMatcherFactory: Mutex + WeakCacheMap<MphValueMatcher>, cached by key
4. TDD CompactDomainMatcherFactory: Mutex + WeakCacheMap<LinearAnyMatcher>
5. TDD CompactDomainMatcher: custom + matchers + values
6. TDD parseDomain: Domain_Substr->Substr, Domain_Regex->Regex, Domain_Domain->Domain, Domain_Full->Full
7. TDD DomainRegistry: mu + factory + matchers, BuildDomainMatcher/Reload
8. TDD DynamicDomainMatcher: atomic state, swap on reload
9. TDD IPRegistry: mu + ipset_factory + matchers, BuildIPMatcher/Reload
10. TDD DynamicIPMatcher: atomic state, swap on reload
11. Add re-exports in matcher/mod.rs
12. Run cargo test -p xray-geodata

Acceptance Criteria:
- DomainMatcherFactory builds correct matcher types
- MphDomainMatcherFactory caches with Weak references
- DomainRegistry reloads dynamically
- IPRegistry builds and reloads IP matchers
- cargo test -p xray-geodata passes

---

### Task 13: 7ua - P2-1.6 AuthenticationReader

File: crates/xray-crypto/src/auth_reader.rs
Go source: common/protocol/cryption/io.go (AuthenticationReader portion)
Description: Authenticated reading with size parsing, padding, and buffer management.

Delegation Recommendation:
- Category: deep - Complex multi-state reader with soft/hard modes
- Skills: [tdd-workflow]

Depends On: Task 1 (fhh - Authenticator) + Task 10 (da8 - ChunkSizeParser)
Blocks: None directly (but needed for protocol integration)

Implementation Steps:
1. TDD AuthenticationReader struct: auth + reader + size_parser + size_bytes Vec + transfer_type + padding + state (size/padding_len/has_size/done)
2. TDD read_size(): read size_bytes, decode with sizeParser, get padding length
3. TDD readBuffer(): read from reader, decrypt with auth.Open
4. TDD readInternal(soft, mb): soft mode for buffered reads, EOF detection, buffer vs bytespool for large data
5. TDD ReadMultiBuffer(): read up to 16 buffers, soft mode after first
6. Add re-exports in lib.rs
7. Run cargo test -p xray-crypto

Acceptance Criteria:
- read_size decodes encrypted size correctly
- readBuffer decrypts data with auth.Open
- readInternal handles EOF and soft/hard modes
- ReadMultiBuffer reads multiple buffers correctly
- cargo test -p xray-crypto passes

---

### Task 14: 8rt - P2-1.7 AuthenticationWriter

File: crates/xray-crypto/src/auth_writer.rs
Go source: common/protocol/cryption/io.go (AuthenticationWriter portion)
Description: Authenticated writing with size encoding, padding, and stream/packet modes.

Delegation Recommendation:
- Category: deep - Complex multi-mode writer with stream/packet logic
- Skills: [tdd-workflow]

Depends On: Task 1 (fhh - Authenticator) + Task 10 (da8 - ChunkSizeParser)
Blocks: None directly

Implementation Steps:
1. TDD AuthenticationWriter struct: auth + writer + size_parser + transfer_type + padding
2. TDD seal(): encrypt size + data + padding, sizeParser.Encode, auth.Seal, random padding
3. TDD writeStream(): split into payloadSize chunks, seal each
4. TDD writePacket(): seal each buffer individually
5. TDD WriteMultiBuffer(): empty->seal empty; stream->writeStream; packet->writePacket
6. Add re-exports in lib.rs
7. Run cargo test -p xray-crypto

Acceptance Criteria:
- seal encrypts size+data+padding correctly
- writeStream chunks data into payloadSize pieces
- writePacket seals each buffer individually
- WriteMultiBuffer handles empty/stream/packet modes
- cargo test -p xray-crypto passes

### Task 15: 3ki - P2-2.8 Rule Parser

File: crates/xray-geodata/src/matcher/attributes.rs (extend) + new rule_parser logic
Go source: common/geodata/rule_parser.go (~265 lines)
Description: Parse geoip:/geosite:/ext: rules into matcher rules.

Delegation Recommendation:
- Category: deep - Rule parsing with multiple prefix types
- Skills: [tdd-workflow]

Depends On: Task 4 (n17 - GeoData Loader) + Task 12 (14h - Domain/IP Registry)
Blocks: None directly (integration layer)

Implementation Steps:
1. TDD DefaultGeoIPDat="geoip.dat", DefaultGeoSiteDat="geosite.dat" constants
2. TDD ParseIPRules: geoip: prefix -> ext: prefix, ext:/ext-ip: prefix, parseGeoIPRule/parseCustomIPRule
3. TDD ParseDomainRule/ParseDomainRules: geosite: prefix -> ext: prefix, ext:/ext-domain: prefix
4. TTD parseCustomDomainRule: regexp:/domain:/full:/keyword:/dotless: prefixes
5. TDD cutReversePrefix: strip ! prefix(es)
6. TDD parseGeoSiteRule: load site data, apply attribute matching
7. TDD parseCustomIPRule: CIDR parsing
8. Add re-exports in lib.rs
9. Run cargo test -p xray-geodata

Acceptance Criteria:
- geoip: prefix loads from default dat file
- geosite: prefix loads from default dat file
- ext: prefix loads from custom path
- Custom rules parse regexp/domain/full/keyword/dotless prefixes
- cutReversePrefix handles ! prefix
- cargo test -p xray-geodata passes

---

### Task 16: 8t4 - P2-3.5 Client Worker

File: crates/xray-mux/src/client.rs
Go source: common/mux/client.go (~419 lines)
Description: ClientManager, WorkerPicker, IncrementalWorkerPicker.

Delegation Recommendation:
- Category: deep - Complex client worker with incremental picking and cleanup
- Skills: [tdd-workflow]

Depends On: Task 5 (3h5 - Session) + Task 6 (3ue - Frame Reader) + Task 7 (wqn - Frame Writer)
Blocks: Task 18 (6mq - Integration Test)

Implementation Steps:
1. TDD ClientManager: Enabled bool + Picker (WorkerPicker trait), Dispatch tries 16 picks
2. TDD WorkerPicker trait: pick_available() -> Option<Worker>
3. TDD IncrementalWorkerPicker: Factory + access (Mutex) + workers Vec + cleanup_task
4. Implement worker lifecycle: create -> pick -> use -> cleanup
5. Add re-exports in lib.rs
6. Run cargo test -p xray-mux

Acceptance Criteria:
- ClientManager dispatches correctly with 16-pick limit
- IncrementalWorkerPicker picks workers incrementally
- Cleanup task removes stale workers
- cargo test -p xray-mux passes

---

### Task 17: bc0 - P2-3.6 Server Dispatcher

File: crates/xray-mux/src/client.rs (or new server.rs)
Go source: common/mux/server.go (~384 lines)
Description: Server, ServerWorker with session management and dispatching.

Delegation Recommendation:
- Category: deep - Complex server dispatcher with session lifecycle
- Skills: [tdd-workflow]

Depends On: Task 5 (3h5 - Session) + Task 6 (3ue - Frame Reader) + Task 7 (wqn - Frame Writer)
Blocks: Task 18 (6mq - Integration Test)

Implementation Steps:
1. TDD Server struct: dispatcher (routing.Dispatcher feature)
2. TDD ServerWorker: dispatcher + link + session_manager + done + timer
3. Implement session lifecycle: accept -> create session -> dispatch -> cleanup
4. Implement frame reading/writing for server side
5. Add re-exports in lib.rs
6. Run cargo test -p xray-mux

Acceptance Criteria:
- Server creates ServerWorkers correctly
- ServerWorker manages session lifecycle
- Frame I/O works for server side
- cargo test -p xray-mux passes

---

### Task 18: 6mq - P2-3.7 Mux Integration Test

File: crates/xray-mux/tests/ (new integration test files)
Go source: Integration test combining all mux components
Description: End-to-end integration test for mux system.

Delegation Recommendation:
- Category: deep - Integration testing across all mux components
- Skills: [tdd-workflow]

Depends On: All above tasks

Implementation Steps:
1. Write integration test: ClientManager -> ClientWorker -> Session -> FrameWriter -> FrameReader -> ServerWorker -> Server
2. Test stream mode: large data through mux stream
3. Test packet mode: individual packets through mux
4. Test session cleanup: verify sessions close properly
5. Test XUDP: GlobalID propagation and expiry
6. Run cargo test -p xray-mux

Acceptance Criteria:
- End-to-end stream mode works
- End-to-end packet mode works
- Sessions clean up properly
- XUDP GlobalID and expiry work
- cargo test -p xray-mux passes
