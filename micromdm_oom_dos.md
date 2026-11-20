# CVE Request – Unbounded Request Body on Unauthenticated Endpoints (OOM DoS)

## 1. Vulnerability Description

The entire MicroMDM codebase contains zero calls to `http.MaxBytesReader`, `io.LimitReader`, or any `Content-Length` validation. Multiple unauthenticated endpoints call `ioutil.ReadAll(r.Body)` directly, reading the entire HTTP request body into memory with no size limit. A single attacker request with a multi-gigabyte body exhausts server memory and crashes the process.

Four unauthenticated endpoints are affected:

- `POST /mdm/enroll` - `ioutil.ReadAll(r.Body)` in `decodeMDMEnrollRequest()` (transport_http.go:64)
- `POST /ota/phase23` - `ioutil.ReadAll(r.Body)` in `decodeOTAPhase2Phase3Request()` (transport_http.go:103)
- `PUT /mdm/connect` - `ioutil.ReadAll(r.Body)` in `mdmRequestBody()` (server.go:101), also read again in `populateDeviceCertificateFromSignRequestHeader()` (server.go:79)
- `PUT /mdm/checkin` - same code path as `/mdm/connect`

The `/mdm/connect` path is especially severe: the body is buffered **twice** - once in the signature-verification middleware and again in the endpoint decoder - doubling memory consumption per request.

<img width="842" height="478" alt="image" src="https://github.com/user-attachments/assets/88a77a60-e692-467e-8622-505414f64733" />

## 2. Impact

Any **unauthenticated** remote attacker can crash the MicroMDM server with a single large HTTP request. No credentials, no enrolled device, no authentication of any kind is required. The attack is trivial, repeatable, and can be sustained to prevent the server from restarting.

- **Complete service denial** - all enrolled devices lose management
- **No audit trail** - the request crashes the process before any meaningful logging
- **Amplification via /mdm/connect** - body is buffered twice, doubling memory consumption per request
- **Trivial automation** - a single-line bash loop sustains the denial indefinitely

## 3. Proof of Concept

The MDM server crashes after receiving too many bytes from a client.
<img width="1902" height="910" alt="image" src="https://github.com/user-attachments/assets/bbd6beb3-3286-493e-98bd-5641d5df6e50" />

## 4. CVSS Score

**CVSS v3.1:** 5.9 - `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`

**CWE**: CWE-770 - Allocation of Resources Without Limits or Throttling

## 5. Recommendation

Wrap all request body readers with `http.MaxBytesReader` at the handler level. Apply a global middleware for defense in depth.
```
// Middleware approach (defense in depth)
func maxBodyMiddleware(maxBytes int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
            next.ServeHTTP(w, r)
        })
    }
}

// Apply to all routes:
handler = maxBodyMiddleware(10 << 20)(handler)  // 10 MB default

// Per-endpoint limits for specific needs (e.g., app upload):
r.Body = http.MaxBytesReader(w, r.Body, 500 << 20)  // 500 MB for uploads
```

## 6. Affected Versions

**Affected**: All versions - no tagged releases with fixes exist. The vulnerabilities are present in the current main branch (latest commit as of 2026-09-23). MicroMDM doesn't use semantic versioning releases - it's built from main.

**Fixed**: None - no patch available at time of disclosure.

## 7. Disclosure Information

**Researcher:** Fabio Cinicolo (cxnturi0n)
**Researcher Organization**: Argo S.p.A.
**Vendor**: MicroMDM (Jesse Peterson, Victor Vrantchan - open-source maintainers)
**Product**: MicroMDM (github.com/micromdm/micromdm)
