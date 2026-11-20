# CVE Request – Path Traversal in App Store Read Endpoints (Plist Read / File Oracle)

## 1. Vulnerability Description

The `POST /v1/apps` endpoint accepts a `filter_name` JSON field to filter apps by name. This value is passed to `Repo.Apps(name)` which joins it unsanitized with the repo path and opens the result with `os.Open()`. The file is then decoded as a plist - plist-format files leak their full contents in the response; non-plist files produce distinct error messages that confirm file existence (information disclosure).
<img width="736" height="328" alt="image" src="https://github.com/user-attachments/assets/160c8144-a594-47c7-8771-b8d1614e51fe" />

The `Repo.Manifest(name)` function accepts an unsanitized `name` parameter, joins it with the repository path via `filepath.Join(r.Path, manifestName)`, and opens the result with `os.Open()`. A `.plist` suffix is appended if not already present, but path traversal sequences still resolve - e.g. `../../../Library/Preferences/com.apple.apsd` becomes `/repo/../../../Library/Preferences/com.apple.apsd.plist`. Valid plist files return their full parsed contents in the response. Non-plist files produce distinguishable errors that confirm file existence (file oracle). Error messages also leak the server's absolute filesystem paths.

<img width="710" height="192" alt="image" src="https://github.com/user-attachments/assets/33aa940f-d695-452f-a82b-552b82a89a23" />

## 2. Impact

Plist file read and file existence oracle on the MDM server. Plist-format files (common on macOS - system configuration, service credentials, app preferences) return full parsed contents. Non-plist files cannot be read, but their existence is confirmed via distinguishable error messages (file existence oracle). Error messages also leak the server's absolute filesystem paths.

## 3. Proof of Concept

It is possible to query the server if an arbitrary file exists on disk, as well as reading arbitrary plist files on disk.
<img width="1888" height="936" alt="image" src="https://github.com/user-attachments/assets/18490a92-88f1-4a8c-8482-81e629b5cc4f" />

## 4. CVSS Score

**CVSS v3.1:** 3.1 - `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N`

CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## 5. Recommendation

Validate `name` is a plain filename with no path separators or `..` sequences before passing it to `filepath.Join`.
```
func (r *Repo) Apps(name string) (map[string]appmanifest.Manifest, error) {
    if name != "" {
        if name != filepath.Base(name) || strings.Contains(name, "..") {
            return nil, fmt.Errorf("invalid app name: %s", name)
        }
        resolved := filepath.Join(r.Path, name)
        if !strings.HasPrefix(resolved, filepath.Clean(r.Path)+string(os.PathSeparator)) {
            return nil, fmt.Errorf("path traversal detected: %s", name)
        }
        mf, err := os.Open(resolved)
        // ...
    }
}
```

```
func (r *Repo) Manifest(name string) (*appmanifest.Manifest, error) {
    if name != filepath.Base(name) || strings.Contains(name, "..") {
        return nil, fmt.Errorf("invalid manifest name: %s", name)
    }
    manifestName := name
    if !strings.HasSuffix(name, ".plist") {
        manifestName = name + ".plist"
    }
    resolved := filepath.Join(r.Path, manifestName)
    if !strings.HasPrefix(resolved, filepath.Clean(r.Path)+string(os.PathSeparator)) {
        return nil, fmt.Errorf("path traversal detected: %s", name)
    }
    file, err := os.Open(resolved)
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
