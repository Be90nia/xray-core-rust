# P2 Feature Implementation Layer - 17 Sub-Task Execution Plan

## Context

Xray-core Rust rewrite project, 1:1 porting from Go. P0 (workspace+protobuf+CI/CD) and P1 (buf/common/proto/features) are complete. P2 base layer (8 sub-tasks: crypto/aead+rand, geodata/protobuf+strmatcher basics, mux/frame, xudp/packet+global_id) are complete.

This plan covers **P2 Feature Implementation Layer - 17 sub-tasks** across 4 crates:
- **xray-crypto**: Authenticator, Chunk, AuthReader/Writer, CryptionReader/Writer (6 tasks)
- **xray-geodata**: MatcherGroup, IP matcher, Loader, ValueMatcher, Registry, RuleParser (6 tasks)
- **xray-mux**: Session, Worker, Client, Server, Integration test (5 tasks)
- **xray-xudp**: Extension integration (1 task)

### Key Constraints
- Buffer has no bytes_mut() - use Vec + extend_from_slice + copy_from_slice
- cfb-mode 0.9 API: Cfb to Encryptor/Decryptor
- TDD: RED to GREEN to IMPROVE for every task
- Minimum 80% test coverage
- Git commit per completed task
- Read C:\Users\Begonia\.config\opencode\rules\rust.md before editing .rs files
## Task Dependency Graph

| Task | ID | Depends On | Reason |
|------|----|-----------|--------|
| 1. Authenticator | fhh | None | Foundation trait, no prerequisites |
| 2. MatcherGroup | 4lj | None | Extends existing matchers.rs |
| 3. IP Matcher | if5 | None | Independent IP matching logic |
| 4. GeoData Loader | n17 | None | File loading, independent |
| 5. Session+XUDP | 3h5 | None | Session management, no prerequisites |
| 6. Frame Reader | 3ue | None | Can stub ChunkStreamReader |
| 7. Frame Writer | wqn | None | Can stub ChunkStreamWriter |
| 8. CryptionReader/Writer | 383 | None | Stream cipher I/O, blocker b5t done |
| 9. XUDP Extension | dsi | None | Blockers chy+ger done |
| 10. Chunk Codec | da8 | Task 1 (fhh) | Uses AEADAuthenticator |
| 11. ValueMatcher/IndexMatcher | 3oc | Task 2 (4lj) | Builds on MatcherGroup |
| 12. Domain/IP Registry | 14h | Task 2 (4lj) + Task 3 (if5) | Uses MatcherGroup + IPMatcher |
| 13. AuthenticationReader | 7ua | Task 1 (fhh) + Task 10 (da8) | Uses Authenticator + ChunkStreamReader |
| 14. AuthenticationWriter | 8rt | Task 1 (fhh) + Task 10 (da8) | Uses Authenticator + ChunkStreamWriter |
| 15. Rule Parser | 3ki | Task 12 (14h) + Task 4 (n17) | Uses Registry + Loader |
| 16. Client Worker | 8t4 | Task 5 (3h5) + Task 6 (3ue) + Task 7 (wqn) | Uses Session + Reader + Writer |
| 17. Server Dispatcher | bc0 | Task 5 (3h5) + Task 6 (3ue) + Task 7 (wqn) | Uses Session + Reader + Writer |
| 18. Mux Integration Test | 6mq | All above | End-to-end validation |

## Parallel Execution Graph

```
Wave 1 (Start Immediately - 9 tasks, NO dependencies):
  Task 1:  fhh - Authenticator (xray-crypto)
  Task 2:  4lj - MatcherGroup (xray-geodata)
  Task 3:  if5 - IP Matcher (xray-geodata)
  Task 4:  n17 - GeoData Loader (xray-geodata)
  Task 5:  3h5 - Session+XUDP (xray-mux)
  Task 6:  3ue - Frame Reader (xray-mux)
  Task 7:  wqn - Frame Writer (xray-mux)
  Task 8:  383 - CryptionReader/Writer (xray-crypto)
  Task 9:  dsi - XUDP Extension (xray-xudp)

Wave 2 (After Wave 1 - 3 tasks):
  Task 10: da8 - Chunk Codec (depends: Task 1)
  Task 11: 3oc - ValueMatcher/IndexMatcher (depends: Task 2)
  Task 12: 14h - Domain/IP Registry (depends: Task 2 + Task 3)

Wave 3 (After Wave 2 - 4 tasks):
  Task 13: 7ua - AuthenticationReader (depends: Task 1 + Task 10)
  Task 14: 8rt - AuthenticationWriter (depends: Task 1 + Task 10)
  Task 15: 3ki - Rule Parser (depends: Task 12 + Task 4)
  Wire Reader/Writer to ChunkStream (depends: Task 10 + Task 6/7)

Wave 4 (After Wave 3 - 2 tasks):
  Task 16: 8t4 - Client Worker (depends: Task 5 + wired Reader/Writer)
  Task 17: bc0 - Server Dispatcher (depends: Task 5 + wired Reader/Writer)

Wave 5 (After Wave 4 - 1 task):
  Task 18: 6mq - Mux Integration Test (depends: ALL)

Critical Path: Task 1 -> Task 10 -> Task 13/14 -> Task 16/17 -> Task 18
Estimated Parallel Speedup: ~55% faster than sequential
```
## Detailed Task Specifications

### Task 1: fhh - P2-1.4 Authenticator (xray-crypto)

**File**: `crates/xray-crypto/src/authenticator.rs`
**Go Source**: `E:\Projcet\Xray-core\common\crypto\auth.go` (350 lines)
**Estimated**: ~400 lines Rust

**Implementation Steps**:
1. Define `BytesGenerator` trait: `fn next(&mut self) -> Vec<u8>`
2. Implement `GenerateEmptyBytes` - returns empty Vec
3. Implement `StaticBytesGenerator` - returns cloned static bytes
4. Implement `IncreasingNonceBytesGenerator` - increments last byte(s) each call
5. Define `Authenticator` trait with methods: nonce_size, overhead, open, seal
6. Define `AdditionalDataGenerator` trait: `fn generate(&self) -> Vec<u8>`
7. Implement `AEADAuthenticator` struct holding AeadCipher + BytesGenerator + AdditionalDataGenerator
8. Implement `AEADAuthenticator::open` - generate nonce + ad, call aead.open
9. Implement `AEADAuthenticator::seal` - generate nonce + ad, call aead.seal
10. Implement `AEADNonceWithSize` - nonce generator with configurable size

**TDD Strategy**:
- RED: Test each BytesGenerator variant (empty, static, increasing)
- RED: Test AEADAuthenticator open/seal roundtrip using AES-128-GCM
- RED: Test AEADAuthenticator with custom additional data
- GREEN: Implement to pass tests
- IMPROVE: Refactor for clarity

**Delegation**: Category `deep` - trait design + crypto integration
**Skills**: [] - Rust + crypto knowledge sufficient
**Commit**: `feat: implement Authenticator trait and AEADAuthenticator`

---

### Task 2: 4lj - P2-2.3 MatcherGroup (xray-geodata)

**File**: `crates/xray-geodata/src/matcher/matchers.rs` (extend existing 506 lines)
**Go Source**: `E:\Projcet\Xray-core\common\strmatcher\` (11 files)
**Estimated**: ~800 additional lines

**Implementation Steps** (add to existing file):
1. Implement `FullMatcherGroup` - HashMap<String, Vec<u32>> for exact match
2. Implement `DomainMatcherGroup` - HashMap + suffix matching with domain layers
3. Implement `SimpleMatcherGroup` - linear scan through patterns
4. Implement `SubstrMatcherGroup` - substring search through all patterns
5. Implement `ACMatcherGroup` - Aho-Corasick automaton (use aho-corasick crate)
6. Implement `MPHMatcherGroup` - Minimal Perfect Hash (use boomphf or custom)
7. All groups implement `MatcherGroup` trait from mod.rs

**TDD Strategy**:
- RED: Test each MatcherGroup with known domain patterns
- RED: Test FullMatcherGroup: exact match vs miss
- RED: Test DomainMatcherGroup: suffix matching
- RED: Test SubstrMatcherGroup: substring matching
- GREEN: Implement each group
- IMPROVE: Optimize lookup performance

**Delegation**: Category `deep` - 6 MatcherGroup variants with different algorithms
**Skills**: [] - algorithm implementation
**Commit**: `feat: implement MatcherGroup variants (Full/Domain/Simple/Substr/AC/MPH)`

---

### Task 3: if5 - P2-2.5 IP Matcher (xray-geodata)

**File**: `crates/xray-geodata/src/matcher/ip.rs`
**Go Source**: `E:\Projcet\Xray-core\common\matching\ip_matcher.go` (1023 lines)
**Estimated**: ~900 lines Rust

**Implementation Steps**:
1. Define `IPMatcher` trait: `fn match_ip(&self, ip: IpAddr) -> bool`
2. Implement `IPSet` - sorted CIDR range set for IPv4/IPv6
3. Implement `HeuristicIPMatcher` - /24 buckets IPv4, /64 buckets IPv6, fallback full scan
4. Implement `GeneralMultiIPMatcher` - Vec of IPMatcher, any match returns true
5. Implement `HeuristicMultiIPMatcher` - heuristic optimization over multiple matchers
6. Implement `IPSetFactory` - cache constructed IP sets by key
7. Implement `build_optimized_ip_matcher` - choose heuristic vs general by entry count

**TDD Strategy**:
- RED: Test IPSet with known CIDR ranges
- RED: Test HeuristicIPMatcher bucket optimization
- RED: Test MultiIPMatcher with multiple ranges
- RED: Test IPSetFactory caching
- GREEN: Implement
- IMPROVE: Benchmark heuristic threshold

**Delegation**: Category `deep` - complex IP matching with heuristic optimization
**Skills**: [] - IP networking + algorithms
**Commit**: `feat: implement IP matcher with heuristic optimization`

---

### Task 4: n17 - P2-2.7 GeoData Loader (xray-geodata)

**File**: `crates/xray-geodata/src/loader.rs`
**Go Source**: `E:\Projcet\Xray-core\common\geodata\geodat_loader.go` (207 lines)
**Estimated**: ~250 lines Rust

**Implementation Steps**:
1. Implement `check_file(path)` - verify file exists and readable
2. Implement `load_file(filename)` - read geodata file from standard paths
3. Implement `find(geo_domain, data)` - streaming protobuf search without full decode
4. Implement `load_ip(country_code)` - load and parse geoip.dat
5. Implement `load_site(country_code)` - load and parse geosite.dat
6. Implement `load_site_with_attrs(country_code, attrs)` - attribute filtering
7. Implement `AttributeMatcher` - match domain attributes (@google etc.)

**TDD Strategy**:
- RED: Test find() with embedded test protobuf data
- RED: Test AttributeMatcher with known attribute strings
- GREEN: Implement
- IMPROVE: Optimize streaming search

**Delegation**: Category `deep` - protobuf streaming + file I/O
**Skills**: [] - protobuf + file I/O
**Commit**: `feat: implement GeoData loader with streaming protobuf search`

---

### Task 5: 3h5 - P2-3.2 Session + XUDP Integration (xray-mux)

**File**: `crates/xray-mux/src/session.rs`
**Go Source**: `E:\Projcet\Xray-core\common\mux\session.go` (252 lines)
**Estimated**: ~300 lines Rust

**Implementation Steps**:
1. Define `TransferType` enum: Stream, Packet
2. Implement `Session` struct with id, transfer_type, closed, done channel, links
3. Implement Session::new(), close(), is_closed()
4. Implement `SessionManager` with sessions HashMap, count, RwLock
5. Implement SessionManager add/get/remove/close
6. Define `XUDP` struct with global_id, status, expire, mux ref
7. Define `XUDPManager` with global Map, cleanup timer
8. Implement XUDPManager register/unregister/cleanup

**TDD Strategy**:
- RED: Test SessionManager add/get/remove lifecycle
- RED: Test Session close propagation
- RED: Test XUDPManager register/cleanup
- GREEN: Implement
- IMPROVE: Add concurrent access tests

**Delegation**: Category `deep` - concurrent state management with RwLock + channels
**Skills**: [] - tokio + async patterns
**Commit**: `feat: implement SessionManager and XUDP integration`
---

### Task 6: 3ue - P2-3.3 Frame Data Reader (xray-mux)

**File**: `crates/xray-mux/src/worker.rs`
**Go Source**: `E:\Projcet\Xray-core\common\mux\reader.go` (59 lines)
**Estimated**: ~120 lines Rust

**Implementation Steps**:
1. Implement `PacketReader` struct holding AsyncRead
2. Implement PacketReader::read() - read 2-byte BE size, then payload as Buffer
3. Implement `StreamReader` struct holding ChunkStreamReader reference
4. Implement StreamReader::read() - delegate to ChunkStreamReader (wire after Task 10)
5. Use trait/stub for ChunkStreamReader dependency initially

**TDD Strategy**:
- RED: Test PacketReader with known byte sequences
- RED: Test PacketReader with zero-length payload
- RED: Test PacketReader with truncated data (error)
- GREEN: Implement
- IMPROVE: Add async timeout tests

**Delegation**: Category `quick` - simple reader, ~120 lines
**Skills**: []
**Commit**: `feat: implement PacketReader and StreamReader`

---

### Task 7: wqn - P2-3.4 Frame Data Writer (xray-mux)

**File**: `crates/xray-mux/src/worker.rs` (extend)
**Go Source**: `E:\Projcet\Xray-core\common\mux\writer.go` (136 lines)
**Estimated**: ~200 lines Rust

**Implementation Steps**:
1. Implement `Writer` struct with dest, writer, id, followup, has_error, transfer_type, global_id, inbound
2. Implement Writer::write_multi_buffer() - Stream: 8KB chunks, Packet: individual buffers
3. Implement stream write path: FrameMetadata + chunk via ChunkStreamWriter
4. Implement packet write path: FrameMetadata + individual buffers
5. Use trait/stub for ChunkStreamWriter initially

**TDD Strategy**:
- RED: Test Writer stream mode small buffer
- RED: Test Writer stream mode large buffer (chunking)
- RED: Test Writer packet mode with multiple buffers
- RED: Test Writer error propagation
- GREEN: Implement
- IMPROVE: Add concurrent write tests

**Delegation**: Category `quick` - moderate writer, ~200 lines
**Skills**: []
**Commit**: `feat: implement frame data Writer with stream/packet modes`

---

### Task 8: 383 - P2-1.8 CryptionReader/Writer (xray-crypto)

**File**: `crates/xray-crypto/src/auth_reader.rs` + `crates/xray-crypto/src/auth_writer.rs`
**Go Source**: `E:\Projcet\Xray-core\common\crypto\io.go` (64 lines)
**Estimated**: ~150 lines Rust total

**Implementation Steps**:
1. Implement `CryptionReader` struct: stream cipher + reader
2. Implement CryptionReader::read() - decrypt via cipher, return Buffer
3. Implement `CryptionWriter` struct: stream cipher + writer
4. Implement CryptionWriter::write() - encrypt via cipher, write to inner
5. Implement CryptionWriter::write_multi_buffer() - encrypt each buffer, write all

**TDD Strategy**:
- RED: Test CryptionReader roundtrip with known plaintext/ciphertext
- RED: Test CryptionWriter roundtrip
- RED: Test CryptionReader/Writer with AES-CFB stream cipher
- GREEN: Implement
- IMPROVE: Add multi-buffer edge cases

**Delegation**: Category `quick` - simple I/O wrappers, ~150 lines
**Skills**: []
**Commit**: `feat: implement CryptionReader and CryptionWriter`

---

### Task 9: dsi - P2-4.3 XUDP Extension Integration (xray-xudp)

**File**: `crates/xray-xudp/src/extension.rs`
**Go Source**: `E:\Projcet\Xray-core\common\xudp\xudp.go` (192 lines)
**Estimated**: ~250 lines Rust

**Implementation Steps**:
1. Implement extension `PacketWriter` wrapping xudp PacketWriter for Mux
2. Implement extension `PacketReader` wrapping xudp PacketReader for Mux
3. Implement global_id extraction from Mux session metadata
4. Implement XUDP status tracking within Mux session
5. Wire PacketWriter/Reader to Mux frame encode/decode

**TDD Strategy**:
- RED: Test extension PacketWriter with known XUDP packets
- RED: Test extension PacketReader roundtrip
- RED: Test global_id extraction
- GREEN: Implement
- IMPROVE: Add integration with real Mux frames

**Delegation**: Category `quick` - integration wiring, ~250 lines
**Skills**: []
**Commit**: `feat: implement XUDP extension integration with Mux`

---

### Task 10: da8 - P2-1.5 Chunk Codec (xray-crypto) [blocked by Task 1]

**File**: `crates/xray-crypto/src/chunk.rs`
**Go Source**: `E:\Projcet\Xray-core\common\crypto\chunk.go` (160 lines)
**Estimated**: ~300 lines Rust

**Implementation Steps**:
1. Define `ChunkSizeDecoder` trait: decode size from bytes
2. Define `ChunkSizeEncoder` trait: encode size to bytes
3. Implement `PlainChunkSizeParser` - 2-byte big-endian size
4. Implement `AEADChunkSizeParser` - encrypt/decrypt size using AEADAuthenticator
5. Define `PaddingLengthGenerator` trait
6. Implement `ChunkStreamReader` - read chunked stream: size + payload + padding
7. Implement `ChunkStreamWriter` - write chunked stream: size + payload + padding

**TDD Strategy**:
- RED: Test PlainChunkSizeParser encode/decode roundtrip
- RED: Test AEADChunkSizeParser with AEADAuthenticator
- RED: Test ChunkStreamReader with known chunked data
- RED: Test ChunkStreamWriter roundtrip
- GREEN: Implement
- IMPROVE: Add edge cases (empty chunks, max size)

**Delegation**: Category `deep` - chunk protocol + crypto integration
**Skills**: []
**Commit**: `feat: implement Chunk codec with AEAD and plain size parsers`

---

### Task 11: 3oc - P2-2.4 ValueMatcher/IndexMatcher (xray-geodata) [blocked by Task 2]

**File**: `crates/xray-geodata/src/matcher/matchers.rs` (extend)
**Go Source**: `E:\Projcet\Xray-core\common\strmatcher\`
**Estimated**: ~400 additional lines

**Implementation Steps**:
1. Implement `LinearIndexMatcher` - linear scan match + index collection
2. Implement `MphIndexMatcher` - MPH-based match + index collection
3. Implement `LinearValueMatcher` - linear scan match + value collection
4. Implement `MphValueMatcher` - MPH-based match + value collection
5. Implement `AnyMatcher` - match any input, always returns true
6. Implement `MatcherSet` combining multiple matchers

**TDD Strategy**:
- RED: Test LinearIndexMatcher with known patterns
- RED: Test MphIndexMatcher with known patterns
- RED: Test MatcherSet with multiple matcher types
- GREEN: Implement
- IMPROVE: Benchmark MPH vs linear threshold

**Delegation**: Category `deep` - multiple matcher algorithms
**Skills**: []
**Commit**: `feat: implement ValueMatcher, IndexMatcher, and MatcherSet`
---

### Task 12: 14h - P2-2.6 Domain/IP Registry (xray-geodata) [blocked by Task 2 + Task 3]

**File**: `crates/xray-geodata/src/matcher/domain.rs` + `crates/xray-geodata/src/matcher/ip.rs`
**Go Source**: domain_registry.go (94 lines), ip_registry.go (135 lines), domain_matcher.go (238 lines)
**Estimated**: ~500 lines Rust total

**Implementation Steps**:
1. Implement `DomainMatcherFactory` trait: create matcher from patterns
2. Implement `MphDomainMatcherFactory` - creates MphDomainMatcher
3. Implement `CompactDomainMatcherFactory` - creates CompactDomainMatcher
4. Implement `CompactDomainMatcher` - space-efficient domain matching
5. Implement `DomainRegistry` - Mutex + factory + matchers, add/match lifecycle
6. Implement `DynamicDomainMatcher` - runtime-updatable domain matcher
7. Implement `IPRegistry` - Mutex + IPSetFactory + matchers
8. Implement `DynamicIPMatcher` - runtime-updatable IP matcher

**TDD Strategy**:
- RED: Test DomainRegistry add/match lifecycle
- RED: Test IPRegistry add/match lifecycle
- RED: Test DynamicDomainMatcher runtime update
- RED: Test CompactDomainMatcher space efficiency
- GREEN: Implement
- IMPROVE: Add concurrent access tests

**Delegation**: Category `deep` - registry pattern with dynamic matchers
**Skills**: []
**Commit**: `feat: implement DomainRegistry, IPRegistry, and dynamic matchers`

---

### Task 13: 7ua - P2-1.6 AuthenticationReader (xray-crypto) [blocked by Task 1 + Task 10]

**File**: `crates/xray-crypto/src/auth_reader.rs`
**Go Source**: `E:\Projcet\Xray-core\common\crypto\auth.go` (AuthenticationReader part)
**Estimated**: ~250 lines Rust

**Implementation Steps**:
1. Implement `AuthenticationReader` struct: auth + reader + size_parser + padding + transfer_type
2. Implement AuthenticationReader::read_multi_buffer() - read up to 16 chunks
3. Each chunk: read encrypted size -> decrypt size -> read payload -> decrypt payload -> verify
4. Handle padding bytes per padding generator
5. Return MultiBuffer from collected decrypted chunks

**TDD Strategy**:
- RED: Test AuthenticationReader with known encrypted stream
- RED: Test AuthenticationReader reads multiple chunks
- RED: Test AuthenticationReader with padding
- RED: Test AuthenticationReader error on corrupted data
- GREEN: Implement
- IMPROVE: Add performance tests

**Delegation**: Category `deep` - crypto protocol reading + multi-chunk
**Skills**: []
**Commit**: `feat: implement AuthenticationReader with multi-chunk decryption`

---

### Task 14: 8rt - P2-1.7 AuthenticationWriter (xray-crypto) [blocked by Task 1 + Task 10]

**File**: `crates/xray-crypto/src/auth_writer.rs`
**Go Source**: `E:\Projcet\Xray-core\common\crypto\auth.go` (AuthenticationWriter part)
**Estimated**: ~250 lines Rust

**Implementation Steps**:
1. Implement `AuthenticationWriter` struct: auth + writer + size_parser + padding
2. Implement write_stream mode: encrypt + chunk each 8KB buffer
3. Implement write_packet mode: encrypt each buffer individually
4. Each chunk: encrypt payload -> encrypt size -> write size + encrypted payload + padding
5. Handle padding generation per padding generator

**TDD Strategy**:
- RED: Test AuthenticationWriter stream mode roundtrip
- RED: Test AuthenticationWriter packet mode roundtrip
- RED: Test AuthenticationWriter with padding
- RED: Test AuthenticationWriter -> AuthenticationReader full roundtrip
- GREEN: Implement
- IMPROVE: Add performance tests

**Delegation**: Category `deep` - crypto protocol writing + multi-chunk
**Skills**: []
**Commit**: `feat: implement AuthenticationWriter with stream/packet encryption`

---

### Task 15: 3ki - P2-2.8 Rule Parser (xray-geodata) [blocked by Task 12 + Task 4]

**File**: `crates/xray-geodata/src/matcher/attributes.rs`
**Go Source**: `E:\Projcet\Xray-core\common\matching\rule_parser.go` (265 lines)
**Estimated**: ~350 lines Rust

**Implementation Steps**:
1. Implement `ParseDomainRules` - parse rule strings into DomainMatcher
2. Implement `ParseIPRules` - parse rule strings into IPMatcher
3. Implement `ParseDomainRule` - parse single rule: geoip:/geosite:/ext:/custom
4. Implement geoip: prefix handler - load from GeoIP data
5. Implement geosite: prefix handler - load from GeoSite data
6. Implement ext: prefix handler - load from external file
7. Implement custom rule handler - direct domain/IP pattern

**TDD Strategy**:
- RED: Test ParseDomainRule with geoip: prefix
- RED: Test ParseDomainRule with geosite: prefix
- RED: Test ParseDomainRule with ext: prefix
- RED: Test ParseDomainRule with custom domain
- RED: Test ParseIPRules with known prefixes
- GREEN: Implement
- IMPROVE: Add error handling edge cases

**Delegation**: Category `deep` - rule parsing with multiple data sources
**Skills**: []
**Commit**: `feat: implement rule parser with geoip/geosite/ext/custom rules`

---

### Task 16: 8t4 - P2-3.5 Client Worker (xray-mux) [blocked by Task 5 + Task 6 + Task 7]

**File**: `crates/xray-mux/src/client.rs`
**Go Source**: `E:\Projcet\Xray-core\common\mux\client.go` (419 lines)
**Estimated**: ~500 lines Rust

**Implementation Steps**:
1. Implement `ClientManager` - manages ClientWorker instances, dispatch/Close
2. Implement `WorkerPicker` trait: pick_worker()
3. Implement `IncrementalWorkerPicker` - round-robin worker selection
4. Implement `ClientWorker` struct: session_manager + link + done + timer + strategy
5. Implement ClientWorker::new() - initialize session and I/O
6. Implement ClientWorker::run() - main event loop for session management
7. Implement ClientWorker session open/close handling
8. Implement WorkerPicker integration with ClientManager

**TDD Strategy**:
- RED: Test ClientManager create/dispatch
- RED: Test IncrementalWorkerPicker round-robin
- RED: Test ClientWorker session lifecycle
- RED: Test ClientWorker with mock I/O
- GREEN: Implement
- IMPROVE: Add concurrency tests

**Delegation**: Category `deep` - complex async state machine + session management
**Skills**: []
**Commit**: `feat: implement ClientWorker with session management`

---

### Task 17: bc0 - P2-3.6 Server Dispatcher (xray-mux) [blocked by Task 5 + Task 6 + Task 7]

**File**: `crates/xray-mux/src/client.rs` (server section, or separate server.rs)
**Go Source**: `E:\Projcet\Xray-core\common\mux\server.go` (384 lines)
**Estimated**: ~450 lines Rust

**Implementation Steps**:
1. Implement `Server` struct wrapping dispatcher
2. Implement Server::dispatch() - accept incoming connections
3. Implement `ServerWorker` struct: dispatcher + link + session_manager + done + timer
4. Implement ServerWorker::new() - initialize server session
5. Implement ServerWorker::run() - main event loop
6. Implement ServerWorker session handling: open/continue/close
7. Implement Server dispatch to downstream handler
8. Wire ServerWorker with SessionManager

**TDD Strategy**:
- RED: Test Server dispatch with mock handler
- RED: Test ServerWorker session lifecycle
- RED: Test ServerWorker with mock I/O
- RED: Test Server close/cleanup
- GREEN: Implement
- IMPROVE: Add concurrency tests

**Delegation**: Category `deep` - complex async server + session management
**Skills**: []
**Commit**: `feat: implement Server dispatcher and ServerWorker`

---

### Task 18: 6mq - P2-3.7 Mux Integration Test (xray-mux) [blocked by ALL]

**File**: `crates/xray-mux/tests/integration_test.rs`
**Estimated**: ~400 lines Rust

**Implementation Steps**:
1. Set up test infrastructure: mock link, mock dispatcher, test data
2. Test Client-Server roundtrip: client sends, server receives, dispatches
3. Test multi-session concurrent communication
4. Test XUDP packet relay through Mux
5. Test session close propagation end-to-end
6. Test error handling: connection drop, corrupt frames
7. Test keep-alive and timeout scenarios
8. Verify all code paths from previous tasks are exercised

**TDD Strategy**:
- This IS the test - validates all prior implementations
- RED: Define expected behaviors as test cases
- GREEN: All tests pass with completed implementations
- IMPROVE: Add stress tests and edge cases

**Delegation**: Category `deep` - integration test across multiple crates
**Skills**: []
**Commit**: `test: add Mux integration tests for client/server/XUDP`

---

## Commit Strategy

Each task produces exactly one atomic commit:
1. All source files for the task changed in one commit
2. Commit message format: `<type>: <description>`
3. Types: feat (new feature), test (integration tests), refactor (structural change)
4. Never commit failing tests - each commit must pass `cargo test`
5. After each commit, run `cargo build` and `cargo test` for the affected crate

**Commit Order** (matches wave execution):
1. `feat: implement Authenticator trait and AEADAuthenticator`
2. `feat: implement MatcherGroup variants (Full/Domain/Simple/Substr/AC/MPH)`
3. `feat: implement IP matcher with heuristic optimization`
4. `feat: implement GeoData loader with streaming protobuf search`
5. `feat: implement SessionManager and XUDP integration`
6. `feat: implement PacketReader and StreamReader`
7. `feat: implement frame data Writer with stream/packet modes`
8. `feat: implement CryptionReader and CryptionWriter`
9. `feat: implement XUDP extension integration with Mux`
10. `feat: implement Chunk codec with AEAD and plain size parsers`
11. `feat: implement ValueMatcher, IndexMatcher, and MatcherSet`
12. `feat: implement DomainRegistry, IPRegistry, and dynamic matchers`
13. `feat: implement AuthenticationReader with multi-chunk decryption`
14. `feat: implement AuthenticationWriter with stream/packet encryption`
15. `feat: implement rule parser with geoip/geosite/ext/custom rules`
16. `feat: implement ClientWorker with session management`
17. `feat: implement Server dispatcher and ServerWorker`
18. `test: add Mux integration tests for client/server/XUDP`

---

## Success Criteria

1. All 17 tasks implemented with passing tests
2. `cargo build` succeeds for entire workspace
3. `cargo test` passes for all 4 crates (xray-crypto, xray-geodata, xray-mux, xray-xudp)
4. Test coverage >= 80% per crate
5. All Go source functionality faithfully ported
6. Git history clean with atomic commits per task

---

## Category and Skills Summary

| Task | Category | Skills | Rationale |
|------|----------|--------|-----------|
| 1 fhh | deep | [] | Trait design + crypto integration |
| 2 4lj | deep | [] | 6 algorithm variants |
| 3 if5 | deep | [] | Complex IP matching + heuristics |
| 4 n17 | deep | [] | Protobuf streaming + file I/O |
| 5 3h5 | deep | [] | Concurrent state management |
| 6 3ue | quick | [] | Simple reader, ~120 lines |
| 7 wqn | quick | [] | Moderate writer, ~200 lines |
| 8 383 | quick | [] | Simple I/O wrappers, ~150 lines |
| 9 dsi | quick | [] | Integration wiring, ~250 lines |
| 10 da8 | deep | [] | Chunk protocol + crypto |
| 11 3oc | deep | [] | Multiple matcher algorithms |
| 12 14h | deep | [] | Registry pattern + dynamic matchers |
| 13 7ua | deep | [] | Crypto protocol reading |
| 14 8rt | deep | [] | Crypto protocol writing |
| 15 3ki | deep | [] | Rule parsing + multiple data sources |
| 16 8t4 | deep | [] | Complex async state machine |
| 17 bc0 | deep | [] | Complex async server |
| 18 6mq | deep | [] | Cross-crate integration testing |

**Skills Evaluation**:
All skills evaluated. OMITTED all special skills because this is a 1:1 Go-to-Rust port with well-defined Go source reference. The codebase patterns (error handling, traits, async, Buffer API) are already established in existing implementations. No domain-specific skills beyond Rust proficiency are needed.
