# Comprehensive Code Review: `src/**`

## Architecture Overview

```
src/
├── core/           # Foundation layer
│   ├── config.pyx  # TOML config loader
│   ├── crypto.pyx  # NaCl encryption/identity
│   └── orm.pyx     # SQLite ORM wrapper
├── net/            # Networking layer
│   ├── connection.pyx  # WebSocket protocol state machine
│   ├── commands.pyx    # Command dispatcher (30+ commands)
│   └── sync.pyx        # P2P federation sync
├── engine/         # Business logic layer
│   ├── ume.pyx     # User management (fixed-width KV store)
│   ├── ame.pyx     # Board/post management
│   ├── keibatsu.pyx    # Reports/punishments
│   └── facade.pyx      # Engine aggregation
└── app/            # Application layer
    ├── server.pyx  # WebSocket server + REPL
    ├── cli.pyx     # Local connection wrapper
    └── main.py     # Entry point
```

---

## Critical Issues

### 1. **SQL Injection Risk in `ame.pyx:354-366`**
```python
if where:
    if not re.match(r"^[a-zA-Z0-9_ =?,.+-]*$", where):
        raise ValueError("Invalid characters in where clause")
```
- Whitelist is too permissive: allows `=`, `?`, `,`, `.`, `+`, `-`
- Doesn't prevent `OR 1=1` patterns or `--` comment sequences
- **Recommendation**: Use parameterized queries exclusively, reject raw WHERE clauses

### 2. **Unbounded String Lengths in Protocol**
- `u8` length prefixes cap strings at 255 bytes
- But code doesn't validate `subject`, `options`, etc. against 255-byte limit before encoding
- `content` uses `u32` (4GB) but board names use `u8` (255 bytes) - inconsistent

### 3. **Race Condition in `ume.pyx`**
- `put()` checks existence then appends - non-atomic under concurrent access
- `upd()` reads, modifies, writes back - lost updates possible
- **Recommendation**: Use file locking (flock/fcntl) or migrate to SQLite

### 4. **Missing Authentication for Admin Commands in `commands.pyx:405-406`**
```python
if not conn.is_administrator():
    return self._build_error(403, "Administrator permission required")
```
- Rule creation/update requires admin
- But `RULE_GET`, `RULE_LIST`, `RULE_GET_BY_NAME` have NO auth check - anonymous can read rules

### 5. **Inconsistent Error Handling**
- Some commands catch `ValueError` specifically (`RULE_CREATE:1029-1030`)
- Others catch generic `Exception` and leak internal details
- Error messages expose internal state: `f"Rule {rule_num} does not exist"` → allows enumeration

---

## Security Concerns

| Issue | Location | Severity |
|-------|----------|----------|
| Path traversal partially blocked | `ame.pyx:186-188` | Medium (allows `-_.`) |
| Board name sanitization inconsistent | `ame.pyx:445` vs `ame.pyx:449` | Low |
| No rate limiting on commands | `commands.pyx` | High |
| Anonymous users can enumerate users | `commands.pyx:212-243` | Medium |
| No replay attack protection | `crypto.pyx` | Medium (nonces not tracked) |
| Hardcoded PBKDF2 iterations | `ume.pyx:41` | Low (600000 is acceptable) |

---

## Code Quality Issues

### 1. **Dead Code / Unused Log Functions**
`commands.pyx:14-25`:
```python
cdef void _log_msg(str msg):
    pass
cdef void _log_hex(str label, bytes data):
    pass
```
These are no-ops. Contrast with `server.pyx` where they're implemented.

### 2. **Duplicated AsyncResult Class**
- Defined identically in `ame.pyx:111-139` and `keibatsu.pyx:20-48`
- Should be in a shared utility module

### 3. **Magic Numbers Everywhere**
- Command codes `0x01`, `0x02`, etc. should be named constants
- Error codes `400`, `401`, `403`, `404`, `409` - should use enum

### 4. **Missing Type Annotations**
- Cython supports `object`, `str`, `int`, etc. but many params are untyped
- `def handle(self, bytes request, object conn)` - `object conn` loses type safety

### 5. **Inconsistent String Encoding**
- `ame.pyx:889`: `creation_date` unpacked as `>Q` (unsigned) 
- `ame.pyx:912`: `creation_date` unpacked as `>q` (signed)
- Protocol docs say `i64` (signed) - `ame.pyx:889` is wrong

---

## Performance Considerations

### 1. **ThreadPoolExecutor Overhead**
- Every board operation spawns a task through executor
- `ame.pyx:341-344`: `get_post()` wraps sync call in async result
- For high-frequency operations, consider in-thread execution with explicit locks

### 2. **Full Table Scan in `ume.pyx:184-199`**
```python
def _find_record_by_username(self, str username):
    # Reads entire file sequentially
```
- No index structure
- O(n) for every lookup
- **Recommendation**: Build in-memory hash index on startup

### 3. **NavDB Sync Bottleneck**
`sync.pyx:111-113`:
```python
if batch:
    nav.upsert_remote_batch(batch)
```
- Batch operation is good, but called after full BOARD_LIST parse
- Consider streaming inserts

---

## Protocol Compliance Issues

### 1. **POST_LIST Response Missing Fields**
Per AGENTS.md, POST_LIST should return:
```
[u64:post_num][i64:creation_date][u8:len][str:subject][u8:len][str:author][u64:root]
```
`commands.pyx:498-502` matches this ✓

### 2. **POST_GET Response Missing `last_modified` Position**
`commands.pyx:436-450` returns:
```
post_num, last_modified, creation_date, last_bumped, closed, sticky, tags, subject, options, root, author, author_registrar, signature, content
```
AGENTS.md specifies this order ✓

### 3. **QUERY_POSTS Response Inconsistent with Spec**
AGENTS.md shows `signature` as last field with `[u8:len][str:signature]`
`commands.pyx:741-742` includes signature ✓

---

## Recommendations

### High Priority:
1. Fix SQL injection in `ame.pyx` - require parameterized values only
2. Add file locking to `ume.pyx` or migrate to SQLite
3. Add rate limiting / connection throttling
4. Add auth checks to RULE_GET, RULE_LIST commands

### Medium Priority:
1. Extract AsyncResult to shared module
2. Define command codes as named constants
3. Add input validation for all string length limits
4. Implement nonce tracking for replay protection

### Low Priority:
1. Remove dead log functions or implement them
2. Add type annotations throughout
3. Build in-memory user index on startup
4. Consolidate string encoding/decoding helpers