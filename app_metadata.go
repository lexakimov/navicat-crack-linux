package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type appMetadata struct {
	version  string
	major    int
	edition  string
	language string
}

func (m appMetadata) productName() string {
	return fmt.Sprintf("Navicat %d", m.major)
}

func (m appMetadata) displayName() string {
	return fmt.Sprintf("Navicat %s %s %s", m.version, m.edition, strings.ToUpper(m.language))
}

func detectAppMetadata(root string) (appMetadata, error) {
	name, err := readDesktopName(filepath.Join(root, "navicat.desktop"))
	if err != nil {
		return appMetadata{}, err
	}

	version, major, err := readEmbeddedVersion(filepath.Join(root, "usr", "bin", "navicat"))
	if err != nil {
		return appMetadata{}, err
	}

	const prefix = "Navicat "
	if !strings.HasPrefix(name, prefix) {
		return appMetadata{}, fmt.Errorf("unexpected desktop application name %q", name)
	}

	nameWithoutProduct := strings.TrimPrefix(name, prefix)
	lastSpace := strings.LastIndexByte(nameWithoutProduct, ' ')
	if lastSpace <= 0 {
		return appMetadata{}, fmt.Errorf("desktop application name lacks an edition and major version: %q", name)
	}

	edition := nameWithoutProduct[:lastSpace]
	desktopMajor, err := strconv.Atoi(nameWithoutProduct[lastSpace+1:])
	if err != nil || desktopMajor != major {
		return appMetadata{}, fmt.Errorf("desktop name %q does not match executable version %s", name, version)
	}

	language, err := readEmbeddedLanguage(filepath.Join(root, "usr", "lib", "liblv.so"))
	if err != nil {
		return appMetadata{}, err
	}

	return appMetadata{version: version, major: major, edition: edition, language: language}, nil
}

func readDesktopName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("Name=")) {
			name := strings.TrimSpace(string(line[len("Name="):]))
			if name != "" {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("Name entry not found in %s", path)
}

// Both supported builds construct the release string in usr/bin/navicat from
// an eight-byte "major.minor." immediate and a following patch-number immediate.
func readEmbeddedVersion(path string) (string, int, error) {
	e, err := elf.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer e.Close()

	section := e.Section(".text")
	if section == nil {
		return "", 0, fmt.Errorf(".text section not found in %s", path)
	}

	code, err := section.Data()
	if err != nil {
		return "", 0, err
	}

	var version string
	var major int
	for i := 0; i+15 <= len(code); i++ {
		if code[i] != 0x48 || code[i+1] < 0xb8 || code[i+1] > 0xbf || code[i+10] != 0xb9 {
			continue
		}

		prefix := strings.TrimRight(string(code[i+2:i+10]), "\x00")
		parts := strings.Split(prefix, ".")
		if len(parts) != 3 || parts[2] != "" {
			continue
		}

		candidateMajor, majorErr := strconv.Atoi(parts[0])
		_, minorErr := strconv.Atoi(parts[1])
		patch := strings.TrimRight(string(code[i+11:i+15]), "\x00")
		_, patchErr := strconv.Atoi(patch)
		if majorErr != nil || minorErr != nil || patchErr != nil || candidateMajor <= 0 {
			continue
		}

		candidate := prefix + patch
		if version != "" && version != candidate {
			return "", 0, fmt.Errorf("ambiguous embedded versions %q and %q in %s", version, candidate, path)
		}

		version, major = candidate, candidateMajor
	}

	if version == "" {
		return "", 0, fmt.Errorf("embedded Navicat version not found in %s", path)
	}

	return version, major, nil
}

func readEmbeddedLanguage(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	e, err := elf.NewFile(f)
	if err != nil {
		return "", err
	}
	defer e.Close()

	lidVA, err := dynamicSymbolVA(e, "_ZN11VersionInfo6getLIDEv")
	if err != nil {
		return "", err
	}

	lidCode, err := readELFVA(f, e, lidVA, 6)
	if err != nil {
		return "", err
	}
	if lidCode[0] != 0xb8 || lidCode[5] != 0xc3 {
		return "", errors.New("unsupported VersionInfo::getLID implementation")
	}
	lid := binary.LittleEndian.Uint32(lidCode[1:5])

	functionVA, err := dynamicSymbolVA(e, "_ZN2LS18obtainLanguageCodeENS_6LangIDE")
	if err != nil {
		return "", err
	}
	function, err := readELFVA(f, e, functionVA, 32)
	if err != nil {
		return "", err
	}

	leaOffset := bytes.Index(function, []byte{0x48, 0x8d, 0x15})
	if leaOffset < 0 || leaOffset+7 > len(function) {
		return "", errors.New("language-code jump table not found")
	}
	tableVA := uint64(int64(functionVA) + int64(leaOffset+7) + int64(int32(binary.LittleEndian.Uint32(function[leaOffset+3:]))))
	entry, err := readELFVA(f, e, tableVA+uint64(lid)*4, 4)
	if err != nil {
		return "", err
	}
	branchVA := uint64(int64(tableVA) + int64(int32(binary.LittleEndian.Uint32(entry))))
	if branchVA < functionVA || branchVA >= functionVA+0x200 {
		return "", errors.New("language-code branch is outside its function")
	}

	branch, err := readELFVA(f, e, branchVA, 12)
	if err != nil {
		return "", err
	}
	if branch[0] != 0xbe || !bytes.Equal(branch[5:8], []byte{0x48, 0x8d, 0x15}) {
		return "", errors.New("unsupported language-code branch")
	}
	length := binary.LittleEndian.Uint32(branch[1:5])
	if length < 2 || length > 10 {
		return "", fmt.Errorf("invalid language-code length %d", length)
	}
	codeVA := uint64(int64(branchVA) + 12 + int64(int32(binary.LittleEndian.Uint32(branch[8:12]))))
	code, err := readELFVA(f, e, codeVA, int(length))
	if err != nil {
		return "", err
	}
	for _, b := range code {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && b != '-' {
			return "", fmt.Errorf("invalid language code %q", code)
		}
	}

	return strings.ToLower(string(code)), nil
}

func dynamicSymbolVA(e *elf.File, name string) (uint64, error) {
	symbols, err := e.DynamicSymbols()
	if err != nil {
		return 0, err
	}
	for _, symbol := range symbols {
		if symbol.Name == name && symbol.Value != 0 {
			return symbol.Value, nil
		}
	}
	return 0, fmt.Errorf("ELF symbol %s not found", name)
}

func readELFVA(f *os.File, e *elf.File, va uint64, size int) ([]byte, error) {
	off, err := vaToOffset(e, va)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, int64(off)); err != nil {
		return nil, err
	}
	return buf, nil
}
