package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func runInteractive(root string, input io.Reader, output io.Writer) error {
	s, err := newInteractiveSession(root, input, output)
	if err != nil {
		return err
	}

	firstRender := true
	for {
		renderInteractiveScreen(s.output, s.header, s.history, s.menuState(), s.terminal && !firstRender)
		firstRender = false

		choice, err := promptLine(s.reader, s.output, "Select: ")
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err
		}

		message, done, err := s.execute(choice)
		if err != nil {
			message = fmt.Sprintf("[%s] Error: %v", choice, err)
		}

		if message != "" {
			s.history = append(s.history, message)
		}

		if done {
			return nil
		}
	}
}

type menuState struct {
	keyReady        bool
	keyExists       bool
	patched         bool
	backupAvailable bool
}

type interactiveSession struct {
	metadata       appMetadata
	library        libraryFile
	keyPath        string
	keyFile        string
	keyExists      bool
	patchCompleted bool
	header         string
	history        []string
	reader         *bufio.Reader
	output         io.Writer
	terminal       bool
}

func newInteractiveSession(root string, input io.Reader, output io.Writer) (*interactiveSession, error) {
	library, err := findLibrary(root)
	if err != nil {
		return nil, err
	}
	metadata, err := detectAppMetadata(root)
	if err != nil {
		return nil, err
	}

	keyFile := privateKeyPath(metadata.version)
	keyExists, keyUsable, err := inspectPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf(
		"Navicat Linux Crack (2026)\n\nhttps://github.com/lexakimov/navicat-linux-crack\n\n%s\nlibcc.so found: %s\nSHA-256: %s ✅\n",
		metadata.displayName(),
		library.path,
		library.profile.sha256,
	)
	if keyExists {
		header += fmt.Sprintf("\nPreviously generated private key found: %s\n", keyFile)
		if !keyUsable {
			header += "Existing private key is invalid; regenerate it with option 2.\n"
		}
	}

	s := &interactiveSession{
		metadata:  metadata,
		library:   library,
		keyFile:   keyFile,
		keyExists: keyExists,
		header:    header,
		reader:    bufio.NewReader(input),
		output:    output,
		terminal:  isTerminalOutput(output),
	}
	if keyUsable {
		s.keyPath = keyFile
	}

	return s, nil
}

func (s *interactiveSession) menuState() menuState {
	return menuState{
		keyReady:        s.keyPath != "",
		keyExists:       s.keyExists,
		patched:         s.patchCompleted,
		backupAvailable: regularFileExists(s.library.path + ".backup"),
	}
}

func (s *interactiveSession) execute(choice string) (message string, done bool, err error) {
	switch choice {
	case "1":
		message, err = s.restoreLibrary()
	case "2":
		message, err = s.generatePrivateKey()
	case "3":
		message, err = s.patchLibrary()
	case "4":
		message, err = s.generateLicenseKey()
	case "5":
		message, err = s.activate()
	case "6":
		if s.terminal {
			renderInteractiveOutput(s.output, s.header, s.history)
		}

		fmt.Fprintln(s.output, colorActionNumber("[6] Good Bye!", s.terminal))

		return "", true, nil
	default:
		message = "Choose 1, 2, 3, 4, 5 or 6."
	}

	return message, false, err
}

func (s *interactiveSession) restoreLibrary() (string, error) {
	if !regularFileExists(s.library.path + ".backup") {
		return "[1] No libcc.so.backup is available.", nil
	}

	if err := restoreLibraryFromBackup(s.library); err != nil {
		return "", err
	}

	s.library.patched = false
	s.patchCompleted = false

	return "[1] Restore libcc.so backup\nRestored: " + s.library.path, nil
}

func (s *interactiveSession) generatePrivateKey() (string, error) {
	if err := saveNewPrivateKey(s.keyFile, s.keyExists); err != nil {
		return "", err
	}

	s.keyPath = s.keyFile
	s.keyExists = true
	s.patchCompleted = false
	message := "[2] Key generated: " + s.keyPath
	if s.library.patched {
		message += "\nRestore and patch libcc.so again to use this key."
	}

	return message, nil
}

func (s *interactiveSession) patchLibrary() (string, error) {
	if s.keyPath == "" {
		return missingPrivateKeyMessage("3", s.keyExists), nil
	}

	if s.library.patched {
		return "[3] Restore libcc.so from backup before patching again.", nil
	}

	if err := patchApplicationLibrary(s.library, s.keyPath); err != nil {
		return "", err
	}

	s.library.patched = true
	s.patchCompleted = true

	return "[3] Patch libcc.so...\nlibcc.so.backup created\nlibcc.so successfully patched!", nil
}

func (s *interactiveSession) generateLicenseKey() (string, error) {
	if s.keyPath == "" {
		return missingPrivateKeyMessage("4", s.keyExists), nil
	}

	var salt [3]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}

	serial, err := generateLicenseKey(s.metadata.major, s.metadata.language, salt)
	if err != nil {
		return "", err
	}

	return "[4] License key: " + serial + "\nLaunch " + s.metadata.productName() + ", enter the license key in the \"Registration\" window, then click Activate.\nIgnore the error, reopen \"Registration\" from the menu, and proceed to the next step.", nil
}

func (s *interactiveSession) activate() (string, error) {
	if !s.patchCompleted {
		return "[5] Patch libcc.so with option 3 first.", nil
	}

	if s.terminal {
		renderInteractiveOutput(s.output, s.header, s.history)
	}

	code, transcript, err := activateInteractive(s.reader, s.output, s.keyPath)
	if err != nil {
		return "", err
	}

	return transcript + "\n\nGenerated Activation Code:\n" + code, nil
}

func inspectPrivateKey(path string) (exists, usable bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}

	if err != nil {
		return false, false, err
	}

	if !info.Mode().IsRegular() {
		return true, false, nil
	}

	_, err = readPrivateKey(path)

	return true, err == nil, nil
}

func missingPrivateKeyMessage(option string, keyExists bool) string {
	if keyExists {
		return "[" + option + "] Existing private key is invalid. Regenerate it with option 2 first."
	}
	return "[" + option + "] Generate a private key with option 2 first."
}

func isTerminalOutput(output io.Writer) bool {
	f, ok := output.(*os.File)
	if !ok {
		return false
	}

	info, err := f.Stat()

	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func renderInteractiveOutput(output io.Writer, header string, history []string) {
	renderInteractiveBody(output, header, history, true)
}

func renderInteractiveScreen(output io.Writer, header string, history []string, state menuState, clear bool) {
	renderInteractiveBody(output, header, history, clear)
	printInteractiveMenu(output, state)
}

func renderInteractiveBody(output io.Writer, header string, history []string, clear bool) {
	if clear {
		fmt.Fprint(output, "\x1b[H\x1b[2J")
	}

	fmt.Fprint(output, header)
	useANSI := isTerminalOutput(output)

	for _, message := range history {
		fmt.Fprintf(output, "\n%s\n", colorActionNumber(message, useANSI))
	}

	fmt.Fprintln(output)
}

func printInteractiveMenu(output io.Writer, state menuState) {
	useANSI := isTerminalOutput(output)
	fmt.Fprintln(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	printMenuItem(output, "[1] Restore libcc.so backup", state.backupAvailable, useANSI)

	if state.keyExists {
		printMenuItem(output, "[2] Regenerate private key", true, useANSI)
	} else {
		printMenuItem(output, "[2] Generate private key", true, useANSI)
	}

	printMenuItem(output, "[3] Patch libcc.so", state.keyReady, useANSI)
	printMenuItem(output, "[4] Generate license key", state.keyReady, useANSI)
	printMenuItem(output, "[5] Activate with activation request", state.patched, useANSI)
	printMenuItem(output, "[6] Exit", true, useANSI)
	fmt.Fprintln(output)
}

func printMenuItem(output io.Writer, label string, enabled, useANSI bool) {
	if !useANSI {
		fmt.Fprintln(output, label)
		return
	}
	if !enabled {
		fmt.Fprintf(output, "%s\x1b[2m%s\x1b[0m\n", colorActionNumber(label[:3], true), label[3:])
		return
	}
	fmt.Fprintln(output, colorActionNumber(label, true))
}

func colorActionNumber(line string, useANSI bool) string {
	if !useANSI || len(line) < 3 || line[0] != '[' || line[1] < '0' || line[1] > '9' || line[2] != ']' {
		return line
	}
	return "\x1b[36m" + line[:3] + "\x1b[0m" + line[3:]
}

func promptLine(reader *bufio.Reader, output io.Writer, prompt string) (string, error) {
	fmt.Fprint(output, prompt)

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}

	return strings.TrimSpace(line), nil
}
