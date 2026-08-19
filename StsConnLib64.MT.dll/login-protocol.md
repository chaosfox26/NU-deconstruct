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
