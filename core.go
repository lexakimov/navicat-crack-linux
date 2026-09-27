package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// These addresses and the SHA-256 identify the original Linux x86-64 17.3.10
// libcc.so. Never use these offsets on a different build.
const (
	originalSHA256                  = "594d51de75803894071a0651d8c9f7017f2bfe7fabacf8a87352b5f1169de3b2"
	keyBuilderVA                    = uint64(0x958ecb0)
	keyBuilderEndVA                 = uint64(0x958ed9e)
	publicKeyStorageVA              = uint64(0x3079000)
	manualWrapperVA                 = keyBuilderVA + 0x40
	appendVA                        = uint64(0x5f0d1f0)
	registrationDialogBuilderVA     = uint64(0x9584ac0)
	registrationDialogVTableEntryVA = uint64(0xb404c98)
	registrationDialogRelocOff      = 0x4949d0
	registrationDialogFuncVA        = uint64(0x95b71a0)
	manualDialogVTableEntryVA       = uint64(0xb404d08)
	manualDialogFuncVA              = uint64(0x9582ae0)
	oldKeySHA256                    = "6ef55cbdbe991339f8b01b5b925f856cfab5c38b4189dbac125f655efd1a1dd5"
	oldKeyBase64                    = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889IqdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginva5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOFR0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmtYyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQawIDAQAB"
)

var originalBuilderPrefix = []byte{
	0x41,
	0x57,
	0xb8,
	0x4d,
	0x49,
	0x00,
	0x00,
	0xba,
	0x49,
	0x42,
	0x00,
	0x00,
	0x41,
	0x56,
	0x41,
	0x55,
}

// libraryProfile contains the build-specific values used by the patcher.
// A new binary is supported only after its checksum and every offset are verified.
type libraryProfile struct {
	title                         string
	productName                   string
	keyFilePrefix                 string
	sha256                        string
	serialVersion                 int
	language                      string
	originalBuilderPrefix         []byte
	oldKeyBase64                  string
	keyBuilderVA                  uint64
	keyBuilderEndVA               uint64
	publicKeyStorageVA            uint64
	manualWrapperVA               uint64
	appendVA                      uint64
	registrationDialogBuilderVA   uint64
	registrationDialogVTableEntry uint64
	registrationDialogRelocOff    int
	registrationDialogFuncVA      uint64
	manualDialogVTableEntryVA     uint64
	manualDialogFuncVA            uint64
	dialogFieldOffset             byte
}

var profile17310 = libraryProfile{
	title:                         "Navicat 17 Premium (EN) Crack (2026)",
	productName:                   "Navicat 17",
	keyFilePrefix:                 "navicat17-crack-key-",
	sha256:                        originalSHA256,
	serialVersion:                 17,
	language:                      "en",
	originalBuilderPrefix:         originalBuilderPrefix,
	oldKeyBase64:                  oldKeyBase64,
	keyBuilderVA:                  keyBuilderVA,
	keyBuilderEndVA:               keyBuilderEndVA,
	publicKeyStorageVA:            publicKeyStorageVA,
	manualWrapperVA:               manualWrapperVA,
	appendVA:                      appendVA,
	registrationDialogBuilderVA:   registrationDialogBuilderVA,
	registrationDialogVTableEntry: registrationDialogVTableEntryVA,
	registrationDialogRelocOff:    registrationDialogRelocOff,
	registrationDialogFuncVA:      registrationDialogFuncVA,
	manualDialogVTableEntryVA:     manualDialogVTableEntryVA,
	manualDialogFuncVA:            manualDialogFuncVA,
	dialogFieldOffset:             0x70,
}

var supportedProfiles = []*libraryProfile{&profile17310}

func privateKeyPath(profile *libraryProfile) string {
	return filepath.Join("/tmp", profile.keyFilePrefix+profile.sha256[:12]+".pem")
}

func saveNewPrivateKey(path string, replace bool) error {
	data, err := makePrivateKeyPEM()
	if err != nil {
		return err
	}

	if !replace {
		return writeNewFile(path, data, 0o600)
	}

	return replaceFileAtomically(path, ".private-key-*", data, 0o600)
}

func makePrivateKeyPEM() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), nil
}

func checkOriginal(data []byte, profile *libraryProfile) (int, error) {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != profile.sha256 {
		return 0, fmt.Errorf("unsupported libcc.so SHA-256: %x", sum)
	}

	e, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer e.Close()

	if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != elf.EM_X86_64 {
		return 0, errors.New("expected ELF64 x86-64, little endian")
	}

	off, err := vaToOffset(e, profile.keyBuilderVA)
	if err != nil {
		return 0, err
	}

	builderBytes, err := fileBytesAt(data, off, len(profile.originalBuilderPrefix))
	if err != nil {
		return 0, err
	}

	if !bytes.Equal(builderBytes, profile.originalBuilderPrefix) {
		return 0, errors.New("key-generator entry bytes differ from the selected build profile")
	}

	return off, nil
}

func vaToOffset(e *elf.File, va uint64) (int, error) {
	for _, p := range e.Progs {
		if p.Type == elf.PT_LOAD && va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			return int(p.Off + va - p.Vaddr), nil
		}
	}

	return 0, fmt.Errorf("VA %#x is not in a file-backed PT_LOAD segment", va)
}

func fileBytesAt(data []byte, off, size int) ([]byte, error) {
	if off < 0 || size < 0 || off > len(data) || size > len(data)-off {
		return nil, fmt.Errorf("file range at offset %#x (%d bytes) is out of bounds", off, size)
	}
	return data[off : off+size], nil
}

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}

	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var key any

		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool

			priv, ok = key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("PKCS#8 key is not RSA")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}

	if err != nil {
		return nil, err
	}

	if priv.N.BitLen() != 2048 {
		return nil, errors.New("RSA key must be 2048 bits")
	}

	if err := priv.Validate(); err != nil {
		return nil, err
	}

	return priv, nil
}

func patchLibrary(data []byte, priv *rsa.PrivateKey, profile *libraryProfile) ([]byte, error) {
	off, err := checkOriginal(data, profile)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(der)
	if len(encoded) != len(profile.oldKeyBase64) {
		return nil, fmt.Errorf("unexpected public key length %d", len(encoded))
	}

	stub, err := makeKeyBuilder([]byte(encoded), profile)
	if err != nil {
		return nil, err
	}
	// The builder must not overlap the next function in this build.
	if profile.keyBuilderVA+uint64(len(stub)) > profile.keyBuilderEndVA {
		return nil, errors.New("key builder replacement overlaps the next function")
	}

	result := bytes.Clone(data)

	builderTarget, err := fileBytesAt(result, off, len(stub))
	if err != nil {
		return nil, err
	}

	copy(builderTarget, stub)

	e, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer e.Close()

	keyOff, err := vaToOffset(e, profile.publicKeyStorageVA)
	if err != nil {
		return nil, err
	}

	keyOriginal, err := fileBytesAt(data, keyOff, len(encoded)+1)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(keyOriginal, make([]byte, len(encoded)+1)) {
		return nil, errors.New("public key storage is not empty in the original library")
	}

	keyTarget, err := fileBytesAt(result, keyOff, len(encoded)+1)
	if err != nil {
		return nil, err
	}

	copy(keyTarget, encoded)
	keyTarget[len(encoded)] = 0

	wrapper, err := makeManualWrapper(profile)
	if err != nil {
		return nil, err
	}

	if profile.manualWrapperVA+uint64(len(wrapper)) > profile.keyBuilderEndVA {
		return nil, errors.New("manual dialog wrapper overlaps the next function")
	}

	wrapperOff, err := vaToOffset(e, profile.manualWrapperVA)
	if err != nil {
		return nil, err
	}

	wrapperTarget, err := fileBytesAt(result, wrapperOff, len(wrapper))
	if err != nil {
		return nil, err
	}

	copy(wrapperTarget, wrapper)

	if err := routeToManualDialog(data, result, profile); err != nil {
		return nil, err
	}

	return result, nil
}

func routeToManualDialog(original, patched []byte, profile *libraryProfile) error {
	e, err := elf.NewFile(bytes.NewReader(original))
	if err != nil {
		return err
	}
	defer e.Close()

	entryOff, err := vaToOffset(e, profile.manualDialogVTableEntryVA)
	if err != nil {
		return err
	}

	manualEntry, err := fileBytesAt(original, entryOff, 8)
	if err != nil {
		return err
	}

	if binary.LittleEndian.Uint64(manualEntry) != profile.manualDialogFuncVA {
		return errors.New("manual-dialog vtable entry differs from the selected build profile")
	}

	slotOff, err := vaToOffset(e, profile.registrationDialogVTableEntry)
	if err != nil {
		return err
	}

	registrationEntry, err := fileBytesAt(original, slotOff, 8)
	if err != nil {
		return err
	}

	if binary.LittleEndian.Uint64(registrationEntry) != profile.registrationDialogFuncVA {
		return errors.New("registration-dialog dispatch differs from the selected build profile")
	}
	// The loader applies this R_X86_64_RELATIVE relocation at startup, so the
	// relocation addend must change together with the vtable bytes.
	r := profile.registrationDialogRelocOff

	relocation, err := fileBytesAt(original, r, 24)
	if err != nil {
		return err
	}

	if binary.LittleEndian.Uint64(relocation[:8]) != profile.registrationDialogVTableEntry ||
		binary.LittleEndian.Uint64(relocation[8:16]) != 8 ||
		binary.LittleEndian.Uint64(relocation[16:24]) != profile.registrationDialogFuncVA {
		return errors.New("registration-dialog relocation differs from the selected build profile")
	}
	// The manual dialog callback reads fields from the normal RegistrationDialog.
	// The wrapper creates it if this is the first registration attempt after startup.
	patchedEntry, err := fileBytesAt(patched, slotOff, 8)
	if err != nil {
		return err
	}

	patchedRelocation, err := fileBytesAt(patched, r, 24)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint64(patchedEntry, profile.manualWrapperVA)
	binary.LittleEndian.PutUint64(patchedRelocation[16:24], profile.manualWrapperVA)

	return nil
}

func makeManualWrapper(profile *libraryProfile) ([]byte, error) {
	if profile.dialogFieldOffset > 0x7f {
		return nil, fmt.Errorf("dialog field offset %#x does not fit an x86 disp8", profile.dialogFieldOffset)
	}
	// SysV AMD64: RDI is CSRegistrationCenter_LINUX*. Preserve it across the
	// constructor call and keep the stack aligned. If the ordinary registration
	// dialog already exists, retain its serial and other entered fields.
	stub := []byte{
		0x53,             // push rbx
		0x48, 0x89, 0xfb, // mov rbx, rdi
		0x48, 0x83, 0x7f, profile.dialogFieldOffset, 0x00, // cmp qword [rdi+offset], 0
		0x75, 0x05, // jne after call
		0xe8, 0, 0, 0, 0, // call create RegistrationDialog
		0x48, 0x89, 0xdf, // mov rdi, rbx
		0x5b,             // pop rbx
		0xe9, 0, 0, 0, 0, // jmp showOfflineActivationDialog
	}
	if err := putRel32(stub[12:16], profile.registrationDialogBuilderVA, profile.manualWrapperVA+16); err != nil {
		return nil, err
	}

	if err := putRel32(stub[21:25], profile.manualDialogFuncVA, profile.manualWrapperVA+25); err != nil {
		return nil, err
	}

	return stub, nil
}

func makeKeyBuilder(encoded []byte, profile *libraryProfile) ([]byte, error) {
	if len(encoded) != len(profile.oldKeyBase64) || bytes.IndexByte(encoded, 0) >= 0 {
		return nil, fmt.Errorf("public key must be %d non-NUL bytes", len(profile.oldKeyBase64))
	}
	// SysV AMD64 ABI: RDI points to the std::string return object. Create an
	// empty string, then call the library's own append(const char*) function.
	// RBX is saved so the call has 16-byte stack alignment.
	stub := []byte{
		0x53,             // push rbx
		0x48, 0x89, 0xfb, // mov rbx, rdi
		0x48, 0x8d, 0x47, 0x10, // lea rax, [rdi+0x10]
		0x48, 0x89, 0x07, // mov [rdi], rax
		0x48, 0xc7, 0x47, 0x08, 0, 0, 0, 0, // mov qword [rdi+8], 0
		0xc6, 0x47, 0x10, 0, // mov byte [rdi+16], 0
		0x48, 0x8d, 0x35, 0, 0, 0, 0, // lea rsi, [rip+key]
		0xe8, 0, 0, 0, 0, // call append(const char*)
		0x5b, 0xc3, // pop rbx; ret
	}
	if err := putRel32(stub[26:30], profile.publicKeyStorageVA, profile.keyBuilderVA+30); err != nil {
		return nil, err
	}

	if err := putRel32(stub[31:35], profile.appendVA, profile.keyBuilderVA+35); err != nil {
		return nil, err
	}

	return stub, nil
}

func putRel32(dst []byte, target, next uint64) error {
	d := int64(target) - int64(next)
	if d < -1<<31 || d > 1<<31-1 {
		return fmt.Errorf("relative branch from %#x to %#x is out of range", next, target)
	}

	binary.LittleEndian.PutUint32(dst, uint32(int32(d)))

	return nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}

	if writeErr == nil {
		writeErr = f.Sync()
	}

	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(path)
		return writeErr
	}

	if closeErr != nil {
		os.Remove(path)
		return closeErr
	}

	return nil
}

func replaceFileAtomically(path, pattern string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}

	n, err := tmp.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return io.ErrShortWrite
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

type libraryFile struct {
	path    string
	profile *libraryProfile
	patched bool
}

func findLibrary(root string) (libraryFile, error) {
	return findLibraryWithProfiles(root, supportedProfiles)
}

func findLibraryWithProfiles(root string, profiles []*libraryProfile) (libraryFile, error) {
	path := filepath.Join(root, "usr", "lib", "libcc.so")

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			prefix := strings.TrimRight(root, string(os.PathSeparator))
			if prefix == "" && !filepath.IsAbs(root) {
				prefix = "."
			}

			return libraryFile{}, fmt.Errorf("File %s\x1b[31m/usr/lib/libcc.so\x1b[0m not found", prefix)
		}

		return libraryFile{}, err
	}

	if !info.Mode().IsRegular() {
		return libraryFile{}, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}

	sum, err := fileSHA256(path)
	if err != nil {
		return libraryFile{}, err
	}

	if profile := profileForSHA256(sum, profiles); profile != nil {
		return libraryFile{path: path, profile: profile}, nil
	}

	if regularFileExists(path + ".backup") {
		backupSum, err := fileSHA256(path + ".backup")
		if err != nil {
			return libraryFile{}, err
		}

		if profile := profileForSHA256(backupSum, profiles); profile != nil {
			return libraryFile{path: path, profile: profile, patched: true}, nil
		}
	}

	var expected []string
	for _, profile := range profiles {
		expected = append(expected, profile.sha256)
	}

	return libraryFile{}, fmt.Errorf(
		"unsupported libcc.so SHA-256: %s (expected %s)",
		sum,
		strings.Join(expected, ", "),
	)
}

func profileForSHA256(sum string, profiles []*libraryProfile) *libraryProfile {
	for _, profile := range profiles {
		if sum == profile.sha256 {
			return profile
		}
	}

	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func patchApplicationLibrary(lib libraryFile, keyPath string) error {
	info, err := os.Lstat(lib.path)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return errors.New("libcc.so is not a regular file")
	}

	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return err
	}

	original, err := os.ReadFile(lib.path)
	if err != nil {
		return err
	}

	patched, err := patchLibrary(original, priv, lib.profile)
	if err != nil {
		return err
	}

	return replaceWithBackup(lib.path, original, patched, info.Mode().Perm())
}

func restoreLibraryFromBackup(lib libraryFile) error {
	backup := lib.path + ".backup"
	if !regularFileExists(backup) {
		return fmt.Errorf("%s is not a regular backup file", backup)
	}

	if !regularFileExists(lib.path) {
		return fmt.Errorf("%s is not a regular file", lib.path)
	}

	sum, err := fileSHA256(backup)
	if err != nil {
		return err
	}

	if sum != lib.profile.sha256 {
		return fmt.Errorf("backup SHA-256 mismatch: %s", sum)
	}

	return os.Rename(backup, lib.path)
}

func replaceWithBackup(path string, original, patched []byte, mode os.FileMode) error {
	backup := path + ".backup"
	if err := writeNewFile(backup, original, mode); err != nil {
		return fmt.Errorf("create backup %s: %w", backup, err)
	}

	return replaceFileAtomically(path, ".libcc.so-patched-*", patched, mode)
}
