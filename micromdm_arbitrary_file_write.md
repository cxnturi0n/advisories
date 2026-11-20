# CVE Request – Arbitrary File Write via Path Traversal in App Upload

## 1. Vulnerability Description

A vulnerability was identified in MicroMDM's App Upload endpoint (PUT /v1/apps) that allows a low-privileged user (possessing the shared API key) to write arbitrary files anywhere on the server filesystem due to insufficient input validation on user-supplied filenames passed to filepath.Join() and os.Create().

The `PUT /v1/apps` endpoint accepts multipart form uploads for app manifests and packages. Two form fields - `app_manifest_filename` and `pkg_name` - control the filename under which the uploaded content is saved. These values are read directly from the HTTP request in `decodeAppUploadRequest()` (upload_app.go:49,54) and passed through `AppService.UploadApp()` (upload_app.go:17-19) to `Repo.SaveFile()` (builtin/appstore.go:22-32) without any sanitization or validation.

`SaveFile()` calls `filepath.Join(r.Path, name)` followed by `os.Create(fname)`. Since `filepath.Join` resolves `..` segments, a crafted filename such as `../../../etc/cron.d/backdoor` escapes the repository directory and creates or overwrites files at arbitrary filesystem locations with the content supplied in the upload.

<img width="694" height="482" alt="image" src="https://github.com/user-attachments/assets/f9709f4e-202c-4cc2-b4ea-b8f19a31c307" />

## 2. Impact

An authenticated attacker (possessing the API key) can write arbitrary files anywhere on the filesystem where the MicroMDM process has write access. This leads to:

- **Remote Code Execution** - if the process runs as root: via cron jobs or systemd units; as non-root: via binary overwrite (on restart) or shell profile overwrite (on next login)
- **Server persistence** - backdoor that survives API key rotation, config changes, and service restarts
- **Integrity/availability of enrolled devices** - the same API key required for this exploit also grants full MDM command authority (EraseDevice, DeviceLock, InstallProfile, etc.) over all enrolled devices via `POST /v1/commands`. The device impact stems from the shared auth model, not the path traversal itself, but amplifies the overall severity of API key compromise.

## 3. Proof of Concept

The vulnerability can be reproduced using the following steps:

Start the Micro MDM server.
<img width="1890" height="264" alt="image" src="https://github.com/user-attachments/assets/614d82e9-089e-464f-b3bc-723417f12cb2" />

Send a PUT request to /v1/apps, populating *app_manifest_filename* and *app_manifest_filedata* with the path traversal payload writing a PHP cmdshell under /var/www/html.
<img width="1840" height="222" alt="image" src="https://github.com/user-attachments/assets/4720c4d8-b383-44a2-b541-53e0159b97a9" />

The arbitrary write occurred successfully and the PHP cmdshell was written under /var/www/html.
<img width="1882" height="696" alt="image" src="https://github.com/user-attachments/assets/d7602c33-6a36-410d-9e4d-8db72f2788d9" />

<img width="1000" height="202" alt="image" src="https://github.com/user-attachments/assets/93f00e57-2c7f-4827-a669-9e69d44ea1f9" />

## 4. CVSS Score

**CVSS v3.1:** 8.1 - `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`

**CVSS v4.0:** 7.2 - `AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`

**CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## 5. Recommendation

The vendor should properly validate and sanitize user-controlled input.
```
func (r *Repo) SaveFile(name string, f io.Reader) error {
    // Reject any path components - only allow plain filenames
    if name != filepath.Base(name) || strings.Contains(name, "..") {
        return fmt.Errorf("invalid filename: %s", name)
    }
    fname := filepath.Join(r.Path, name)
    // Double-check the resolved path is within the repo
    if !strings.HasPrefix(fname, filepath.Clean(r.Path)+string(os.PathSeparator)) {
        return fmt.Errorf("path traversal detected: %s", name)
    }
    file, err := os.Create(fname)
    // ...
}
```

## 6. Affected Versions

**Affected**: All versions - no tagged releases with fixes exist. The vulnerabilities are present in the current main branch (latest commit as of 2026-09-23). MicroMDM doesn't use semantic versioning releases - it's built from main.

**Fixed**: None - no patch available at time of disclosure.

## 7. Disclosure Information

- **Researcher:** Fabio Cinicolo (cxnturi0n)
- **Researcher Organization:** Argo S.p.A.
- **Vendor:** MicroMDM (Jesse Peterson, Victor Vrantchan - open-source maintainers)
- **Product:** MicroMDM (github.com/micromdm/micromdm)
