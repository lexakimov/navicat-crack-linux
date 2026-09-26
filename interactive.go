package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type menuState struct {
	keyReady        bool
	keyExists       bool
	patched         bool
	backupAvailable bool
}

type interactiveSession struct {
	library        libraryFile
	keyFile        string
	keyPath        string
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

	keyFile := cryptographicKeyPath(library.profile)

	keyExists, keyUsable, err := inspectCryptographicKey(keyFile)
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf(
		"%s\n\nlibcc.so found: %s\nSHA-256: %s ✅\n",
		library.profile.title,
		library.path,
		library.profile.sha256,
	)
	if keyExists {
		header += fmt.Sprintf("\nPreviously generated cryptographic key found: %s\n", keyFile)
		if !keyUsable {
			header += "Existing cryptographic key is invalid; regenerate it with option 2.\n"
		}
	}

	s := &interactiveSession{
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
		message, err = s.regenerateKey()
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

		fmt.Fprintln(s.output, "[6] Good Bye!")

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

func (s *interactiveSession) regenerateKey() (string, error) {
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
		return missingCryptographicKeyMessage("3", s.keyExists), nil
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
		return missingCryptographicKeyMessage("4", s.keyExists), nil
	}

	var salt [3]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}

	serial, err := generateSerial(s.library.profile.serialVersion, s.library.profile.language, salt)
	if err != nil {
		return "", err
	}

	return "[4] License key: " + serial + "\nLaunch " + s.library.profile.productName + ", enter the license key in the 'Registration...' window, then click Activate. Ignore the error, reopen 'Registration...' from the menu, and proceed to the next step.", nil
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

func inspectCryptographicKey(path string) (exists, usable bool, err error) {
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

func missingCryptographicKeyMessage(option string, keyExists bool) string {
	if keyExists {
		return "[" + option + "] Existing cryptographic key is invalid. Regenerate it with option 2 first."
	}
	return "[" + option + "] Generate a cryptographic key with option 2 first."
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

	for _, message := range history {
		fmt.Fprintf(output, "\n%s\n", message)
	}

	fmt.Fprintln(output)
}

func printInteractiveMenu(output io.Writer, state menuState) {
	useDim := isTerminalOutput(output)
	fmt.Fprintln(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	printMenuItem(output, "[1] Restore libcc.so backup", state.backupAvailable, useDim)

	if state.keyExists {
		fmt.Fprintln(output, "[2] Regenerate cryprographic key")
	} else {
		fmt.Fprintln(output, "[2] Generate cryprographic key")
	}

	printMenuItem(output, "[3] Patch libcc.so", state.keyReady, useDim)
	printMenuItem(output, "[4] Generate license key", state.keyReady, useDim)
	printMenuItem(output, "[5] Activate with activation request", state.patched, useDim)
	fmt.Fprintln(output, "[6] Exit")
	fmt.Fprintln(output)
}

func printMenuItem(output io.Writer, label string, enabled, useDim bool) {
	if enabled {
		fmt.Fprintln(output, label)
	} else if useDim {
		fmt.Fprintf(output, "\x1b[2m%s\x1b[0m\n", label)
	} else {
		fmt.Fprintln(output, label)
	}
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

func activateInteractive(reader *bufio.Reader, output io.Writer, keyPath string) (string, string, error) {
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return "", "", err
	}

	fmt.Fprintln(output, "[5] Manual activation")

	name, err := promptLine(reader, output, "Enter Name: ")
	if err != nil {
		return "", "", err
	}

	if name == "" {
		return "", "", errors.New("name is required")
	}

	var transcript strings.Builder
	fmt.Fprintf(&transcript, "[5] Manual activation\nEnter Name: %s\n", name)

	org, err := promptLine(reader, output, "Enter Organization (optional): ")
	if err != nil {
		return "", "", err
	}

	fmt.Fprintf(&transcript, "Enter Organization (optional): %s\n\n", org)

	requestPrompt := "Paste the Request Code (Base64). A blank line also finishes input:"
	fmt.Fprintln(output, "\n"+requestPrompt)
	fmt.Fprintln(&transcript, requestPrompt)

	var request strings.Builder
	for {
		line, readErr := promptLine(reader, output, "> ")
		if errors.Is(readErr, io.EOF) && request.Len() == 0 {
			return "", "", io.EOF
		}

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", "", readErr
		}

		if line == "" {
			break
		}

		fmt.Fprintf(&transcript, "> %s\n", line)
		request.WriteString(strings.Join(strings.Fields(line), ""))

		if request.Len() > 8192 {
			return "", "", errors.New("activation request is too long")
		}

		if decoded, decodeErr := base64.StdEncoding.DecodeString(
			request.String(),
		); decodeErr == nil &&
			len(decoded) == priv.Size() {
			break
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	response, _, err := makeActivationResponse(priv, request.String(), name, org, time.Now())
	if err != nil {
		return "", "", err
	}

	return response, strings.TrimRight(transcript.String(), "\n"), nil
}
