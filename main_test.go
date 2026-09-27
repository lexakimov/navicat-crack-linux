package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveredOriginalKey(t *testing.T) {
	sum := sha256.Sum256([]byte(oldKeyBase64))
	if hex.EncodeToString(sum[:]) != oldKeySHA256 {
		t.Fatal("recovered public key digest changed")
	}

	der, err := base64.StdEncoding.DecodeString(oldKeyBase64)
	if err != nil {
		t.Fatal(err)
	}

	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() != 2048 {
		t.Fatal("recovered key is not RSA-2048")
	}
}

func TestPrivateKeyPathAndRegeneration(t *testing.T) {
	want := filepath.Join("/tmp", "navicat17-crack-key-"+originalSHA256[:12]+".pem")
	if got := privateKeyPath(&profile17310); got != want {
		t.Fatalf("key path = %q, want %q", got, want)
	}

	other := profile17310
	other.sha256 = "abcdef012345" + originalSHA256[12:]
	if got := privateKeyPath(&other); got != filepath.Join("/tmp", "navicat17-crack-key-abcdef012345.pem") {
		t.Fatalf("another build's key path = %q", got)
	}

	path := filepath.Join(t.TempDir(), "key.pem")
	if err := saveNewPrivateKey(path, false); err != nil {
		t.Fatal(err)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := readPrivateKey(path); err != nil {
		t.Fatalf("new key is invalid: %v", err)
	}

	if err := saveNewPrivateKey(path, true); err != nil {
		t.Fatal(err)
	}

	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("regeneration left the old key unchanged")
	}

	if _, err := readPrivateKey(path); err != nil {
		t.Fatalf("regenerated key is invalid: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestInspectPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	exists, usable, err := inspectPrivateKey(path)
	if err != nil || exists || usable {
		t.Fatalf("missing key: exists=%t usable=%t err=%v", exists, usable, err)
	}

	if err := saveNewPrivateKey(path, false); err != nil {
		t.Fatal(err)
	}

	exists, usable, err = inspectPrivateKey(path)
	if err != nil || !exists || !usable {
		t.Fatalf("valid key: exists=%t usable=%t err=%v", exists, usable, err)
	}

	if err := os.WriteFile(path, []byte("invalid PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	exists, usable, err = inspectPrivateKey(path)
	if err != nil || !exists || usable {
		t.Fatalf("invalid key: exists=%t usable=%t err=%v", exists, usable, err)
	}
}

func TestReplaceWithBackupPreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libcc.so")
	original := []byte("original library")
	patched := []byte("patched library")

	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := replaceWithBackup(path, original, patched, 0o644); err != nil {
		t.Fatal(err)
	}

	backup, err := os.ReadFile(path + ".backup")
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup = %q, error = %v", backup, err)
	}

	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, patched) {
		t.Fatalf("current = %q, error = %v", current, err)
	}

	if err := replaceWithBackup(path, patched, []byte("another patch"), 0o644); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing backup should not be overwritten: %v", err)
	}

	current, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(current, patched) {
		t.Fatalf("library changed after backup conflict: %q, error = %v", current, err)
	}
}

func TestFindLibraryRejectsWrongFileAndSymlink(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "usr", "lib", "libcc.so")
	if err := os.MkdirAll(filepath.Dir(lib), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(lib, []byte("wrong version"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := findLibrary(root); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected checksum error, got %v", err)
	}

	if err := os.Remove(lib); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(root, "target"), lib); err != nil {
		t.Fatal(err)
	}

	if _, err := findLibrary(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestFindLibraryRequiresExactPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "libcc.so"), []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := findLibrary(root)
	want := "File " + root + "\x1b[31m/usr/lib/libcc.so\x1b[0m not found"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestFindLibrarySelectsProfileFromOriginalOrBackup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "usr", "lib", "libcc.so")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	original := []byte("a different build")
	sum := sha256.Sum256(original)
	profile := &libraryProfile{sha256: hex.EncodeToString(sum[:])}
	profiles := []*libraryProfile{&profile17310, profile}

	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	lib, err := findLibraryWithProfiles(root, profiles)
	if err != nil || lib.profile != profile || lib.patched {
		t.Fatalf("original profile selection: lib=%+v err=%v", lib, err)
	}

	if err := os.WriteFile(path+".backup", original, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("patched build"), 0o644); err != nil {
		t.Fatal(err)
	}

	lib, err = findLibraryWithProfiles(root, profiles)
	if err != nil || lib.profile != profile || !lib.patched {
		t.Fatalf("patched profile selection: lib=%+v err=%v", lib, err)
	}
}

func TestFileBytesAtRejectsOutOfBoundsRanges(t *testing.T) {
	data := []byte{1, 2, 3}
	for _, test := range []struct{ off, size int }{{-1, 1}, {0, -1}, {2, 2}, {4, 0}} {
		if _, err := fileBytesAt(data, test.off, test.size); err == nil {
			t.Fatalf("range %d:%d should fail", test.off, test.off+test.size)
		}
	}

	if got, err := fileBytesAt(data, 1, 2); err != nil || !bytes.Equal(got, data[1:]) {
		t.Fatalf("valid range: %v, %v", got, err)
	}
}

func TestPatchLibraryWithOriginalFixture(t *testing.T) {
	path := os.Getenv("NAVICAT_ORIGINAL_LIBCC")
	if path == "" {
		t.Skip("set NAVICAT_ORIGINAL_LIBCC to test the verified 17.3.10 binary")
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	patched, err := patchLibrary(original, key, &profile17310)
	if err != nil {
		t.Fatal(err)
	}

	if len(patched) != len(original) || bytes.Equal(patched, original) {
		t.Fatal("patch must modify the library without changing its size")
	}
}

func TestMenuItemsHaveNoLockExplanations(t *testing.T) {
	var output bytes.Buffer
	printInteractiveMenu(&output, menuState{})

	menu := output.String()
	if !strings.HasPrefix(menu, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n[1] Restore libcc.so backup\n") {
		t.Fatalf("menu separator missing or misplaced: %q", menu)
	}

	if strings.Contains(menu, "locked until") {
		t.Fatalf("menu contains lock explanations: %q", menu)
	}

	for _, label := range []string{"[1] Restore libcc.so backup", "[2] Generate private key", "[3] Patch libcc.so", "[4] Generate license key", "[5] Activate with activation request", "[6] Exit"} {
		if !strings.Contains(menu, label+"\n") {
			t.Fatalf("menu item missing: %s in %q", label, menu)
		}
	}

	output.Reset()
	printInteractiveMenu(&output, menuState{keyExists: true})

	if !strings.Contains(output.String(), "[2] Regenerate private key\n") ||
		strings.Contains(output.String(), "[2] Generate private key\n") {
		t.Fatalf("existing key should change option 2 label: %q", output.String())
	}

	output.Reset()
	printMenuItem(&output, "[5] Activate with activation request", false, true)

	if output.String() != "\x1b[36m[5]\x1b[0m\x1b[2m Activate with activation request\x1b[0m\n" {
		t.Fatalf("disabled item should have a cyan number and dimmed text: %q", output.String())
	}

	output.Reset()
	printMenuItem(&output, "[5] Activate with activation request", true, true)

	if output.String() != "\x1b[36m[5]\x1b[0m Activate with activation request\n" {
		t.Fatalf("enabled item should have a cyan number: %q", output.String())
	}
}

func TestActionNumberColorOnlyInTerminal(t *testing.T) {
	line := "[4] License key: NAVC-TEST-TEST-TEST\nNext step"
	if got := colorActionNumber(line, false); got != line {
		t.Fatalf("plain output contains ANSI codes: %q", got)
	}
	want := "\x1b[36m[4]\x1b[0m License key: NAVC-TEST-TEST-TEST\nNext step"
	if got := colorActionNumber(line, true); got != want {
		t.Fatalf("only the action number should be cyan: %q", got)
	}
}

func TestCommandOutputRendersAboveSingleMenu(t *testing.T) {
	var output bytes.Buffer
	renderInteractiveScreen(
		&output,
		"Navicat 17 Premium (EN) Crack (2026)\n\nlibcc.so found: /app/usr/lib/libcc.so\nSHA-256: test ✅\n",
		[]string{
			"[2] Key generated: /tmp/key.pem",
			"License key: NAVC-TEST-TEST-TEST",
		},
		menuState{keyReady: true},
		false,
	)

	screen := output.String()
	if strings.Count(screen, "[2] Generate private key") != 1 {
		t.Fatalf("menu should be rendered once: %q", screen)
	}

	if !strings.HasSuffix(screen, "[6] Exit\n\n") {
		t.Fatalf("Select prompt needs a blank line after the actions: %q", screen)
	}

	if strings.Index(screen, "License key: ") > strings.Index(screen, "[1] Restore libcc.so backup") {
		t.Fatalf("command output should appear above the menu: %q", screen)
	}
}

func TestInteractiveActivationAcceptsWrappedRequest(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(t.TempDir(), "private.pem")
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	request := `{"P":"Linux","K":"example"}`

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(request))
	if err != nil {
		t.Fatal(err)
	}

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	input := "Alice\nLab\n" + encoded[:80] + "\n" + encoded[80:] + "\n"

	var output bytes.Buffer

	code, transcript, err := activateInteractive(bufio.NewReader(strings.NewReader(input)), &output, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(output.String(), "[5] Manual activation\nEnter Name: ") ||
		!strings.Contains(output.String(), "Paste the Request Code (Base64)") {
		t.Fatalf("activation prompts missing from output: %q", output.String())
	}

	if !strings.Contains(
		transcript,
		"[5] Manual activation\nEnter Name: Alice\nEnter Organization (optional): Lab\n\nPaste the Request Code (Base64)",
	) {
		t.Fatalf("activation transcript has wrong wording or line breaks: %q", transcript)
	}

	signature, err := base64.StdEncoding.DecodeString(code)
	if err != nil || len(signature) != priv.Size() {
		t.Fatalf("invalid activation code: %v", err)
	}
}

func TestKeyBuilderPayload(t *testing.T) {
	stub, err := makeKeyBuilder([]byte(oldKeyBase64), &profile17310)
	if err != nil {
		t.Fatal(err)
	}

	if len(stub) != 37 {
		t.Fatalf("payload length = %d", len(stub))
	}

	leaTarget := int64(keyBuilderVA+30) + int64(int32(binary.LittleEndian.Uint32(stub[26:30])))
	callTarget := int64(keyBuilderVA+35) + int64(int32(binary.LittleEndian.Uint32(stub[31:35])))
	if leaTarget != int64(publicKeyStorageVA) || callTarget != int64(appendVA) {
		t.Fatalf("wrong payload target(s): lea=%#x call=%#x", leaTarget, callTarget)
	}

	if keyBuilderVA+uint64(len(stub)) >= keyBuilderEndVA {
		t.Fatal("key builder overlaps the next function")
	}
}

func TestManualWrapperTargets(t *testing.T) {
	stub, err := makeManualWrapper(&profile17310)
	if err != nil {
		t.Fatal(err)
	}

	if len(stub) != 25 || stub[9] != 0x75 || stub[10] != 0x05 {
		t.Fatalf("unexpected wrapper guard: %x", stub)
	}

	callTarget := int64(manualWrapperVA+16) + int64(int32(binary.LittleEndian.Uint32(stub[12:16])))
	jumpTarget := int64(manualWrapperVA+25) + int64(int32(binary.LittleEndian.Uint32(stub[21:25])))
	if callTarget != int64(registrationDialogBuilderVA) || jumpTarget != int64(manualDialogFuncVA) {
		t.Fatalf("wrong wrapper target(s): call=%#x jump=%#x", callTarget, jumpTarget)
	}

	if manualWrapperVA+uint64(len(stub)) >= keyBuilderEndVA {
		t.Fatal("manual wrapper overlaps the next function")
	}

	invalid := profile17310
	invalid.dialogFieldOffset = 0x80
	if _, err := makeManualWrapper(&invalid); err == nil {
		t.Fatal("a positive offset that does not fit disp8 must be rejected")
	}
}

func TestActivationResponseSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	request := `{"P":"Linux","K":"example"}`

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(request))
	if err != nil {
		t.Fatal(err)
	}

	code, decoded, err := makeActivationResponse(
		priv,
		base64.StdEncoding.EncodeToString(ciphertext),
		"Alice",
		"Lab",
		time.Unix(1700000000, 0),
	)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != request {
		t.Fatalf("decrypted request = %q", decoded)
	}

	signature, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		t.Fatal(err)
	}

	want := `{"K":"example","N":"Alice","O":"Lab","T":1700000000}`
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, 0, []byte(want), signature); err != nil {
		t.Fatalf("activation response signature is invalid: %v", err)
	}
}
