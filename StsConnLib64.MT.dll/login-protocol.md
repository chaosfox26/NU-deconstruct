# WildStar STS login protocol — reverse-engineered from StsConnLib64.MT.dll

Derived entirely from the client binary (this deconstruction) — a fact source.
No emulator/NF code. Addresses are from `StsConnLib64.MT.dll` (image base
`0x180000000`). Reproduce with `tools/bin-re.py`.

## Transport

STS is an HTTP-shaped **text protocol** (clear-text before SRP completes):

```
POST /<Service>/<Message> STS/1.0\r\n
l:<body byte length>\r\n
s:<sequence>\r\n
\r\n
<xml body>
```

Replies: `STS/1.0 <code> <text>\r\n` + the same `l:`/`s:` headers + XML body. The
client matches a reply to its request by the `s:` sequence.

## Login flow (SRP-6a, email/password)

```
/Sts/Connect      <Connect><ConnType>400</ConnType>…<Build>…</Build></Connect>   -> 200 OK (empty)
/Auth/LoginStart  <Request><LoginName>…</LoginName><NetAddress>…</NetAddress></Request>
                  -> reply: <Content><KeyData>…</KeyData></Content>   (SRP salt + B)
/Auth/KeyData     <Request><KeyData>…</KeyData></Request>            (SRP A + M1)
                  -> reply: <Content><KeyData>…</KeyData></Content>   (SRP M2)
/Auth/RequestGameToken -> reply carries <Token>
```

There is also a token/signed-challenge path (`CLoginTokenStartTxnNotify`, fields
`ServerRand` / `ServerPublicKey` / `ServerSignature`) — a separate variant.

## The KeyData blob (the crux)

`<KeyData>` carries the SRP values as a length-delimited binary blob. Format
(from `CSrpClient` state-0 processor `0x18002d4e0`):

```
[ u32 LE len1 ][ len1 bytes ]  [ u32 LE len2 ][ len2 bytes ]
     field1 = salt                   field2 = B
```

The parser requires the blob to be consumed **exactly** (no trailing bytes;
`0x18002D5DE: cmp rax, rsi; jne error`). Two length-prefixed fields.

## The handler chain (RTTI + vtables)

- `CLoginStart` message vtable `0x180125088`; its **method[5] = `0x18000A320`** is
  the LoginStart-reply handler.
- The **SRP client** (`CSrpClient`, vtable `0x18012CDB8`) is a member at
  **`[this+0x60]`**. The handler loads it and calls `CSrpClient::method[5]`
  (`0x18002DE00`), a state machine keyed on `[srp+8]`: state 0 → `0x18002d4e0`
  (parse salt+B), state 2 → `0x18002d3b0`.
- `0x18002d4e0` splits the blob (above), then **converts B to a bignum and
  validates `B < N`** (`0x18002D60D`; `jns error`). SRP uses standard OpenSSL
  primitives (`crypto/srp/srp_lib.c`, `ssl/tls_srp.c`) — **big-endian bignums**.

## Root cause of "Unhandled NC Platform Error 15"

A server reply whose B is not a valid big-endian bignum `< N` fails that
validation → the STS layer returns an error the platform maps to **"Unhandled NC
Platform Error 15."** Concretely: WildStar's *game-channel* SRP variant emits
little-endian, block-reversed bignums; the **STS channel uses standard OpenSSL
SRP (big-endian)**. B (and the SRP hashing) must follow the OpenSSL convention on
the STS channel — they are two different SRP variants sharing N/g.

## Method addresses (StsConnLib, RE'd)

| what | address |
|---|---|
| LoginStart send + SRP-client create | `0x180006F20` (factory `0x18002CFB0`, stored `[this+0x60]`) |
| LoginStart reply handler (CLoginStart m[5]) | `0x18000A320` |
| CSrpClient state dispatch (m[5]) | `0x18002DE00` |
| CSrpClient state-0 (salt+B parse + B<N validate) | `0x18002d4e0` |
| base64 codec | `0x18001F310`, `0x180081610` |

## CONFIRMED reply schema (2026-08-19, full RE of the parser)

Disassembly of the LoginStart-reply handler (real entry `0x18000A350`) and the
SRP state-0 parser (`0x18002d4e0`) pins the whole schema to certainty:

1. **Envelope.** `reply.vtbl[0x60]()` fetches a **content object**; null → error
   (client sets state 4). The literal tags `<Content>`/`</Content>` are present
   in the binary. (List transactions like VerifiedIPList instead use
   `<Reply type="array"><Items>…` — a different envelope per transaction type.)
2. **Field.** `content.vtbl[0xe0](out, "KeyData", -1)` = `GetField("KeyData")`.
3. **Encoding.** The `<KeyData>` value is **standard base64** (alphabet
   `ABC…xyz0123456789+/`, present at VA `0x18012B200`; `Content-Transfer-Encoding:
   base64`), decoded to a binary blob before the SRP parser (which reads binary
   `u32` length prefixes).
4. **Blob layout** (parser `0x18002d4e0`, exact-consume — total must equal blob
   length or it fails):
   ```
   [u32 LE len1][salt = len1 bytes][u32 LE len2][B = len2 bytes]
   ```
5. **B validation.** B is read **big-endian** and checked **B < N** (`jns` →
   error). Confirms **standard SRP-6a**, big-endian.

A valid LoginStart reply body — **confirmed byte-for-byte against a live capture
of the real server's own STS** (behavioral oracle) — has the root element
**`<Reply>`** (NOT `<Content>`; the `<Content>` literal exists in the binary but
is used elsewhere):

```
STS/1.0 200 OK\r\nl:<bodyLen>\r\ns:<seq>R\r\n\r\n<Reply>\n<KeyData>BASE64( [u32 LE saltLen][salt][u32 LE BLen][B big-endian] )</KeyData>\n</Reply>\n
```

The reply status line, `l:` (body byte count), and `s:<seq>R` (transaction code
with the reply `R` marker) mirror the request; the `<KeyData>` value is standard
base64 of the length-prefixed SRP blob.

The outgoing client request that this provokes is
`<Request><KeyData>BASE64([u32 LE ALen][A][u32 LE M1Len][M1])</KeyData></Request>`
(request builder at `0x18000A4F0`+, field setter `0x1800296d0`).

## The SRP is NCSoft's own, not OpenSSL's built-in

`..\..\..\Services\Srp\Srp.cpp` (VA `0x18012CDF8`, referenced at `0x18002CFBD`)
— NCSoft implemented SRP-6a themselves over OpenSSL 1.0.1i's **bignum + SHA**
primitives (both SHA-1 and SHA-256 are linked). So the hash choice is NCSoft's,
not OpenSSL's SRP default; it is resolved against the client's own M1 at wire
time (ground truth), not assumed.

## RTTI transaction map (reply parsers)

`CLoginStartTxnNotify`, `CKeyDataTxnNotify`, `CLoginTokenStartTxnNotify`,
`CTokenKeyDataTxnNotify`, and `CStsConnTxnNotifyOne<CRequestGameToken>` etc. —
one `*TxnNotify` per STS transaction; the class-specific reply handler is the
last vtable slot.

## Client redirect (from the stock client's own launch params)

The client is **100% stock** (the running `WildStar64.exe` + `StsConnLib64.MT.dll`
are byte-identical to the pristine CDN 16042 install). It is redirected to a
private server purely by its **own command-line parameters** — no binary patch,
no injection:

```
WildStar64.exe /auth <host> /authNc <host> /lang <l> /patcher <host> /SettingsKey WildStar /realmDataCenterId 9
```

`/auth` and `/authNc` = the STS/auth host; STS is plaintext (a stock client
accepts the redirect because there is no TLS/cert on the STS channel).

## Reply status line: `STS/1.0 200  OK` (TWO spaces)

The success status line is `STS/1.0 200  OK` — **two spaces** between `200` and
`OK`. A single-space `STS/1.0 200 OK` is silently discarded by the client's
reply parser for a real transaction (Connect/Ping keepalives tolerate it), so the
transaction times out and retries, then surfaces as "NC Platform Error 15". Full
success reply frame:

```
STS/1.0 200  OK\r\nl:<bodyLen>\r\ns:<seq>R\r\n\r\n<Reply>\n<KeyData>BASE64(blob)</KeyData>\n</Reply>\n
```

---

# SOLVED (2026-08-19): the STS SRP is WildStar's GAME SRP, read LITTLE-ENDIAN

**Correction to the earlier "standard OpenSSL SRP, big-endian" reading above —
that was wrong.** The STS SRP is *not* standard big-endian SRP-6a. It is
WildStar's **game SRP**: every bignum is **little-endian**, hashes are twisted by
**ReverseUInt32** (4-byte word-order reversal), and the session key is
**interleaved**. Reading it big-endian is byte-order-inverted at every layer,
which is why standard SRP never reproduced a single proof.

Confirmed to certainty: the modulus + the entire key-derivation were recovered by
using a **known-credential account's stored verifier as a ground-truth oracle**
(`v = g^x mod N` must reproduce the stored value), and the real 16042 client's own
proof then VERIFIES against a server implementing exactly this.

## Parameters

- **N** = the WildStar SRP prime, **interpreted little-endian**:
  `E306EBC0…AAFEE` read as a little-endian byte array (NOT big-endian).
- **g** = 2  (as the 4-byte LE constant `02 00 00 00` where it is hashed).
- Byte helpers:
  - `LeToBig(b)` = interpret bytes as an unsigned little-endian integer.
  - `BigToLe(v)` = the integer's little-endian bytes.
  - `ReverseUInt32(h)` = reverse the ORDER of the 4-byte words of `h`
    (word[i] → position len−4−i·... i.e. `[w0 w1 … w7] → [w7 … w1 w0]`, words intact).

## Key derivation (all values little-endian)

```
x  = LeToBig( ReverseUInt32( SHA256( salt || SHA256(username ":" password) ) ) )
v  = g^x mod N                                   (verifier, stored little-endian)
k  = LeToBig( ReverseUInt32( SHA256( N || g ) ) )
B  = ( k*v + g^b ) mod N          (server ephemeral b; B sent as 128-byte LE)
A  = g^a mod N                    (client ephemeral a; A sent little-endian)
u  = LeToBig( ReverseUInt32( SHA256( A || B ) ) )
S  = (A · v^u)^b mod N            (server)   =   (B − k·g^x)^(a + u·x) mod N  (client)
K  = InterleaveSessionKey( LE128(S) )        (RFC-2945-style odd/even split, SHA256 each, interleave -> 64 bytes)
M1 = SHA256( (H(N) XOR H(g)) || SHA256(username) || salt || A || B || K )     (client proof)
M2 = SHA256( A || M1 || K )                                                    (server proof)
```

`InterleaveSessionKey(s)`: from the 128-byte LE `s`, take bytes from the end in
odd/even positions into two halves, SHA256 each half, interleave the two digests
byte-by-byte → the 64-byte session key.

## Wire (recap, unchanged)

- Envelope `<Reply>`; status line `STS/1.0 200  OK` (two spaces); `s:<seq>R`.
- `<KeyData>` = base64 of a length-delimited blob:
  - LoginStart reply: `[u32 LE saltLen][salt][u32 LE BLen][B]` (B = 128-byte LE).
  - KeyData request (client): `[u32 ALen][A][u32 M1Len][M1]`.
  - KeyData reply (server): `[u32 M2Len][M2]` (M2 = 32 bytes).

This matches WildStar's game-channel SRP (the same `ReverseUInt32` + little-endian
+ interleave), so the STS and game channels share one SRP primitive.
