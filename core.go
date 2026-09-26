package main

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
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

var originalBuilderPrefix = []byte{0x41, 0x57, 0xb8, 0x4d, 0x49, 0x00, 0x00, 0xba, 0x49, 0x42, 0x00, 0x00, 0x41, 0x56, 0x41, 0x55}

func makePrivateKeyPEM() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), nil
}

func cryptographicKeyPath() string {
	return filepath.Join("/tmp", "navicat17-crack-key-"+originalSHA256[:12]+".pem")
}

func saveNewPrivateKey(path string, replace bool) error {
	data, err := makePrivateKeyPEM()
	if err != nil {
		return err
	}
	if !replace {
		return writeNewFile(path, data, 0600)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".navicat17-crack-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func checkOriginal(data []byte) (int, error) {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != originalSHA256 {
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
	off, err := vaToOffset(e, keyBuilderVA)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(data[off:off+len(originalBuilderPrefix)], originalBuilderPrefix) {
		return 0, errors.New("key-generator entry bytes differ from expected 17.3.10 build")
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

func patchLibrary(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	off, err := checkOriginal(data)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	if len(encoded) != len(oldKeyBase64) {
		return nil, fmt.Errorf("unexpected public key length %d", len(encoded))
	}
	stub, err := makeKeyBuilder([]byte(encoded))
	if err != nil {
		return nil, err
	}
	// The original builder ends at 0x958ed9e. Its old inline-key replacement
	// ran past that boundary and overwrote the next function.
	if keyBuilderVA+uint64(len(stub)) > keyBuilderEndVA {
		return nil, errors.New("key builder replacement overlaps the next function")
	}
	result := bytes.Clone(data)
	copy(result[off:off+len(stub)], stub)
	e, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer e.Close()
	keyOff, err := vaToOffset(e, publicKeyStorageVA)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data[keyOff:keyOff+len(encoded)+1], make([]byte, len(encoded)+1)) {
		return nil, errors.New("public key storage is not empty in the original library")
	}
	copy(result[keyOff:keyOff+len(encoded)], encoded)
	result[keyOff+len(encoded)] = 0
	wrapper, err := makeManualWrapper()
	if err != nil {
		return nil, err
	}
	if manualWrapperVA+uint64(len(wrapper)) > keyBuilderEndVA {
		return nil, errors.New("manual dialog wrapper overlaps the next function")
	}
	wrapperOff, err := vaToOffset(e, manualWrapperVA)
	if err != nil {
		return nil, err
	}
	copy(result[wrapperOff:wrapperOff+len(wrapper)], wrapper)
	if err := routeToManualDialog(data, result); err != nil {
		return nil, err
	}
	return result, nil
}

func routeToManualDialog(original, patched []byte) error {
	e, err := elf.NewFile(bytes.NewReader(original))
	if err != nil {
		return err
	}
	defer e.Close()
	entryOff, err := vaToOffset(e, manualDialogVTableEntryVA)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(original[entryOff:entryOff+8]) != manualDialogFuncVA {
		return errors.New("manual-dialog vtable entry differs from expected 17.3.10 build")
	}
	slotOff, err := vaToOffset(e, registrationDialogVTableEntryVA)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(original[slotOff:slotOff+8]) != registrationDialogFuncVA {
		return errors.New("registration-dialog dispatch differs from expected 17.3.10 build")
	}
	// The loader applies this R_X86_64_RELATIVE relocation at startup, so the
	// relocation addend must change together with the vtable bytes.
	r := registrationDialogRelocOff
	if binary.LittleEndian.Uint64(original[r:r+8]) != registrationDialogVTableEntryVA ||
		binary.LittleEndian.Uint64(original[r+8:r+16]) != 8 ||
		binary.LittleEndian.Uint64(original[r+16:r+24]) != registrationDialogFuncVA {
		return errors.New("registration-dialog relocation differs from expected 17.3.10 build")
	}
	// The manual dialog callback reads fields from the normal RegistrationDialog
	// at center+0x70. The wrapper creates it if this is the first registration
	// attempt after startup, preventing a null dereference at 0xa9c4947.
	binary.LittleEndian.PutUint64(patched[slotOff:slotOff+8], manualWrapperVA)
	binary.LittleEndian.PutUint64(patched[r+16:r+24], manualWrapperVA)
	return nil
}

func makeManualWrapper() ([]byte, error) {
	// SysV AMD64: RDI is CSRegistrationCenter_LINUX*. Preserve it across the
	// constructor call and keep the stack aligned. If the ordinary registration
	// dialog already exists, retain its serial and other entered fields.
	stub := []byte{
		0x53,             // push rbx
		0x48, 0x89, 0xfb, // mov rbx, rdi
		0x48, 0x83, 0x7f, 0x70, 0x00, // cmp qword [rdi+0x70], 0
		0x75, 0x05, // jne after call
		0xe8, 0, 0, 0, 0, // call create RegistrationDialog
		0x48, 0x89, 0xdf, // mov rdi, rbx
		0x5b,             // pop rbx
		0xe9, 0, 0, 0, 0, // jmp showOfflineActivationDialog
	}
	if err := putRel32(stub[12:16], registrationDialogBuilderVA, manualWrapperVA+16); err != nil {
		return nil, err
	}
	if err := putRel32(stub[21:25], manualDialogFuncVA, manualWrapperVA+25); err != nil {
		return nil, err
	}
	return stub, nil
}

func makeKeyBuilder(encoded []byte) ([]byte, error) {
	if len(encoded) != 392 || bytes.IndexByte(encoded, 0) >= 0 {
		return nil, errors.New("public key must be 392 non-NUL bytes")
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
	if err := putRel32(stub[26:30], publicKeyStorageVA, keyBuilderVA+30); err != nil {
		return nil, err
	}
	if err := putRel32(stub[31:35], appendVA, keyBuilderVA+35); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
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

var languageSignatures = map[string][2]byte{
	"en": {0xac, 0x88}, "zh-cn": {0xce, 0x32}, "zh-tw": {0xaa, 0x99},
	"ja": {0xad, 0x82}, "pl": {0xbb, 0x55}, "es": {0xae, 0x10},
	"fr": {0xfa, 0x20}, "de": {0xb1, 0x60}, "ko": {0xb5, 0x60},
	"ru": {0xee, 0x16}, "pt": {0xcd, 0x49},
}

func generateSerial(version int, language string, salt [3]byte) (string, error) {
	if version < 16 || version >= 32 {
		return "", errors.New("this generator supports versions 16 through 31")
	}
	sig, ok := languageSignatures[language]
	if !ok {
		return "", fmt.Errorf("unsupported language %q", language)
	}
	data := [10]byte{0x68, 0x2a, salt[0], salt[1], salt[2], sig[0], sig[1], 0x65, byte((version - 16) << 4), 0x32}
	key := [8]byte{0xe9, 0x7f, 0xb0, 0x60, 0x77, 0x45, 0x90, 0xae}
	block, err := des.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	block.Encrypt(data[2:10], data[2:10])
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data[:])
	s = strings.NewReplacer("I", "8", "O", "9").Replace(s)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16], nil
}

func makeActivationResponse(priv *rsa.PrivateKey, requestBase64, name, org string, when time.Time) (string, string, error) {
	clean := strings.Join(strings.Fields(requestBase64), "")
	ciphertext, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", "", err
	}
	if len(ciphertext) != priv.Size() {
		return "", "", fmt.Errorf("request size is %d bytes; expected %d", len(ciphertext), priv.Size())
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return "", "", fmt.Errorf("request does not decrypt with this private key: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(plain, &obj); err != nil {
		return "", "", fmt.Errorf("request is not JSON: %w", err)
	}
	if obj == nil {
		return "", "", errors.New("request is not a JSON object")
	}
	delete(obj, "P")
	obj["N"], _ = json.Marshal(name)
	obj["O"], _ = json.Marshal(org)
	obj["T"], _ = json.Marshal(when.Unix())
	response, err := json.Marshal(obj)
	if err != nil {
		return "", "", err
	}
	if len(response) > 240 {
		return "", "", fmt.Errorf("response JSON is %d bytes; maximum 240", len(response))
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, 0, response)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(sig), string(plain), nil
}

func findLibrary(root string) (string, bool, bool, error) {
	path := filepath.Join(root, "usr", "lib", "libcc.so")
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			prefix := strings.TrimRight(root, string(os.PathSeparator))
			if prefix == "" && !filepath.IsAbs(root) {
				prefix = "."
			}
			return "", false, false, fmt.Errorf("File %s\x1b[31m/usr/lib/libcc.so\x1b[0m not found", prefix)
		}
		return "", false, false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, false, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return "", false, false, err
	}
	backupAvailable := regularFileExists(path + ".backup")
	if sum == originalSHA256 {
		return path, false, backupAvailable, nil
	}
	if backupAvailable {
		backupSum, err := fileSHA256(path + ".backup")
		if err != nil {
			return "", false, false, err
		}
		if backupSum == originalSHA256 {
			return path, true, true, nil
		}
	}
	return "", false, false, fmt.Errorf("unsupported libcc.so SHA-256: %s (expected %s)", sum, originalSHA256)
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

func patchApplicationLibrary(libPath, keyPath string) error {
	info, err := os.Lstat(libPath)
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
	original, err := os.ReadFile(libPath)
	if err != nil {
		return err
	}
	patched, err := patchLibrary(original, priv)
	if err != nil {
		return err
	}
	return replaceWithBackup(libPath, original, patched, info.Mode().Perm())
}

func restoreLibraryFromBackup(libPath string) error {
	backup := libPath + ".backup"
	if !regularFileExists(backup) {
		return fmt.Errorf("%s is not a regular backup file", backup)
	}
	if !regularFileExists(libPath) {
		return fmt.Errorf("%s is not a regular file", libPath)
	}
	sum, err := fileSHA256(backup)
	if err != nil {
		return err
	}
	if sum != originalSHA256 {
		return fmt.Errorf("backup SHA-256 mismatch: %s", sum)
	}
	return os.Rename(backup, libPath)
}

func replaceWithBackup(path string, original, patched []byte, mode os.FileMode) error {
	backup := path + ".backup"
	if err := writeNewFile(backup, original, mode); err != nil {
		return fmt.Errorf("create backup %s: %w", backup, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".libcc.so-patched-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(patched); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
