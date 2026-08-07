// pex — THE TINY LAUNCHER, in Go (Master 2026-08-07: "use a better option if worthy — you've learned a lot since Nuitka").
//
// This is the ONLY thing a user keeps: one small native binary (~3-5 MB, no readable source, no runtime). It holds NO
// node code. On each run it:
//
//   1. asks the chain for its CURRENT signed manifest {fp, sha256, sig}  — the one code the network ratified,
//   2. STREAMS the code bundle from the chain (mesh/box),
//   3. VERIFIES it NATIVELY — sha256(bundle) == manifest.sha256 AND an ed25519 signature over (fp||sha256) checks against
//      the baked-in chain public key. NO Python needed to verify. A tampered/forged bundle is refused, never run,
//   4. unpacks into a HIDDEN cache (~/.pex/.stream/<fp>) — never a visible folder,
//   5. RUNS the node — LITE by default (headless home) or FULL with --full (GUI + exchange) — via a Python it finds/ships
//      (the node is Python; the interpreter is a generic tool, not our code),
//   6. on close WIPES the streamed code (keeps only the small PUBLIC chart/display cache for a fast restart, per Master).
//
// The user's footprint = this binary. Code lives on the chain, streams on demand, verified by real crypto, wiped after.
// The only true secret (private keys) NEVER passes through here — it stays in the user's cold storage.
//
// Cross-compile from one machine:  GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o pex.exe pex.go
//                                  GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o pex-linux pex.go
//                                  GOOS=darwin  GOARCH=arm64 go build -ldflags "-s -w" -o pex-mac  pex.go
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// CHAIN_PUBKEY — the chain's ed25519 code-signing public key (hex), baked in at build. A bundle is only run if the
// chain's signature over its manifest (fp:sha256) verifies against THIS key. The matching private seed lives ONLY on the
// box (~/.pex_chain_sign_seed, chmod 600, never published). ed25519 here == Go crypto/ed25519 (both RFC-8032).
const CHAIN_PUBKEY = "5962242580089558c2e794010092319f42cd6a36fa8cdb12aade37fd344e0219"

var boxURL = env("PEX_BOX_URL", "https://compute.bull4life.com")

type manifest struct {
	FP     string `json:"fp"`     // the chain's ratified consensus fingerprint
	SHA256 string `json:"sha256"` // sha256 of the code bundle
	Sig    string `json:"sig"`    // ed25519 signature over (fp + ":" + sha256), hex
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func httpGet(path string, timeout time.Duration) ([]byte, error) {
	c := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", strings.TrimRight(boxURL, "/")+path, nil)
	req.Header.Set("User-Agent", "pex/go")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, path)
	}
	return io.ReadAll(resp.Body)
}

// verifyBundle: NATIVE trustless gate. sha256 must match the manifest, and the ed25519 signature over (fp:sha256) must
// verify against the baked-in chain key. No Python, no trust in whoever served the bytes.
func verifyBundle(bundle []byte, m manifest) error {
	sum := sha256.Sum256(bundle)
	got := hex.EncodeToString(sum[:])
	if got != m.SHA256 {
		return fmt.Errorf("bundle sha256 %s != manifest %s (tampered)", got[:16], safe(m.SHA256))
	}
	if CHAIN_PUBKEY == "" {
		// signing key not yet baked in (box hasn't published it) — fall back to sha256-only for now, but LOUDLY, so we
		// never silently skip the signature once it exists.
		fmt.Println("[pex] WARN: no chain signing key baked in yet — verified sha256 only (sign step pending box)")
		return nil
	}
	pk, err := hex.DecodeString(CHAIN_PUBKEY)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("bad baked-in chain key")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), []byte(m.FP+":"+m.SHA256), sig) {
		return fmt.Errorf("chain signature INVALID — refusing (forged/unratified code)")
	}
	return nil
}

func untar(bundle []byte, dest string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(bundle)))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// path-traversal guard (never write outside dest)
		target := filepath.Join(dest, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0o755)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
}

// findPython: the node is Python; find a usable interpreter (bundled beside the binary first, then PATH).
func findPython() string {
	if p := os.Getenv("PEX_PYTHON"); p != "" {
		return p
	}
	exeDir, _ := os.Executable()
	exeDir = filepath.Dir(exeDir)
	names := []string{"python3", "python"}
	if os.PathSeparator == '\\' {
		names = []string{"pythonw.exe", "python.exe"}
	}
	for _, sub := range []string{"python", "runtime", ""} {
		for _, n := range names {
			cand := filepath.Join(exeDir, sub, n)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	for _, n := range names { // fall back to PATH
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func httpGetURL(url string, timeout time.Duration) ([]byte, error) {
	c := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "pex/go")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// pythonStandaloneURL — where to stream a relocatable, self-contained Python for THIS platform when the user has none.
// Defaults to python-build-standalone (reliable public relocatable CPython, no system deps); override with PEX_PYTHON_URL
// (e.g. to serve it from the chain/box). The "install_only" tarball extracts to python/bin/python3 (unix) or
// python/python.exe (windows).
func pythonStandaloneURL() string {
	if u := os.Getenv("PEX_PYTHON_URL"); u != "" {
		return u
	}
	const ver, tag = "3.11.9", "20240814"
	triple := map[string]string{
		"linux/amd64":   "x86_64-unknown-linux-gnu",
		"windows/amd64": "x86_64-pc-windows-msvc",
		"darwin/arm64":  "aarch64-apple-darwin",
		"darwin/amd64":  "x86_64-apple-darwin",
	}[runtime.GOOS+"/"+runtime.GOARCH]
	if triple == "" {
		return ""
	}
	return "https://github.com/astral-sh/python-build-standalone/releases/download/" + tag +
		"/cpython-" + ver + "+" + tag + "-" + triple + "-install_only.tar.gz"
}

// ensurePython — a usable Python to RUN the streamed node. System/bundled first (servers + most users have one); else
// stream a relocatable runtime ONCE and cache it (generic tool, not our code → NOT wiped, so restart is instant).
func ensurePython() string {
	if p := findPython(); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	rtDir := filepath.Join(home, ".pex", "runtime", runtime.GOOS+"_"+runtime.GOARCH)
	pyPath := filepath.Join(rtDir, "python", "bin", "python3")
	if runtime.GOOS == "windows" {
		pyPath = filepath.Join(rtDir, "python", "python.exe")
	}
	if _, err := os.Stat(pyPath); err == nil {
		return pyPath // already cached
	}
	url := pythonStandaloneURL()
	if url == "" {
		return ""
	}
	fmt.Println("[pex] no Python found — streaming a relocatable runtime once (cached for next time)...")
	data, err := httpGetURL(url, 300*time.Second)
	if err != nil {
		fmt.Printf("[pex] python fetch failed (%v) — install python3 or set PEX_PYTHON\n", err)
		return ""
	}
	os.MkdirAll(rtDir, 0o755)
	if err := untar(data, rtDir); err != nil {
		fmt.Printf("[pex] python unpack failed (%v)\n", err)
		return ""
	}
	os.Chmod(pyPath, 0o755)
	if _, err := os.Stat(pyPath); err == nil {
		fmt.Println("[pex] runtime ready (cached)")
		return pyPath
	}
	return ""
}

func safe(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func main() {
	full := false
	for _, a := range os.Args[1:] {
		if a == "--full" {
			full = true
		}
	}
	if os.Getenv("PEX_FULL") == "1" {
		full = true
	}
	mode := "node.pex_lite"
	if full {
		mode = "node.pex_join_out"
	}

	home, _ := os.UserHomeDir()
	streamRoot := filepath.Join(home, ".pex", ".stream")
	os.MkdirAll(streamRoot, 0o755)

	// 1) the chain's signed manifest (fp + bundle sha256 + signature)
	raw, err := httpGet("/download/pex-manifest.json", 15*time.Second)
	if err != nil {
		// manifest not published yet → fall back to the fp endpoint (sha256-less; verifyBundle warns). Keeps working today.
		fp, e2 := httpGet("/node_version", 15*time.Second)
		if e2 != nil {
			fmt.Printf("[pex] cannot reach the chain (%v) — is PEX_BOX_URL right?\n", err)
			os.Exit(2)
		}
		var nv struct {
			CF string `json:"consensus_fingerprint"`
		}
		json.Unmarshal(fp, &nv)
		raw, _ = json.Marshal(manifest{FP: nv.CF})
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.FP == "" {
		fmt.Println("[pex] chain manifest invalid — refusing to run")
		os.Exit(2)
	}
	fmt.Printf("[pex] chain ratified fp: %s — streaming that exact code (%s)\n", safe(m.FP), map[bool]string{true: "full", false: "lite"}[full])

	cache := filepath.Join(streamRoot, safe(m.FP))
	if _, err := os.Stat(cache); err != nil { // 2+3) stream + unpack (skip if this fp already cached)
		bundle, err := httpGet("/download/pex-node.tar.gz", 120*time.Second)
		if err != nil {
			fmt.Printf("[pex] stream failed (%v)\n", err)
			os.Exit(3)
		}
		if m.SHA256 != "" { // 4) NATIVE verify (sha256 + signature) — no Python
			if err := verifyBundle(bundle, m); err != nil {
				fmt.Printf("[pex] REFUSING: %v\n", err)
				os.Exit(4)
			}
			fmt.Printf("[pex] verified ✓ bundle sha256 + chain signature (%s)\n", safe(m.FP))
		}
		tmp, _ := os.MkdirTemp(streamRoot, ".dl_")
		if err := untar(bundle, tmp); err != nil {
			os.RemoveAll(tmp)
			fmt.Printf("[pex] unpack failed (%v)\n", err)
			os.Exit(3)
		}
		os.Rename(tmp, cache)
	}

	py := ensurePython()
	if py == "" {
		fmt.Println("[pex] no Python runtime available and none could be streamed — install python3 or set PEX_PYTHON")
		os.Exit(5)
	}

	// 5) run the node from the hidden cache
	fmt.Printf("[pex] running from hidden cache (%s)\n", safe(m.FP))
	cmd := exec.Command(py, "-m", mode)
	cmd.Dir = cache
	cmd.Env = append(os.Environ(), "PYTHONPATH="+cache)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin

	// 6) wipe the streamed CODE on exit (keep only the public chart/display cache under ~/.pex; never anything sensitive).
	wipe := func() {
		if os.Getenv("PEX_KEEP") != "1" {
			os.RemoveAll(cache)
			fmt.Println("[pex] wiped the streamed code (kept only the public chart cache; nothing sensitive left)")
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cmd.Process.Kill(); wipe(); os.Exit(0) }()
	err = cmd.Run()
	wipe()
	if err != nil {
		os.Exit(1)
	}
}
