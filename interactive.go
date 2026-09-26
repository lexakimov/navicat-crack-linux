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

func runInteractive(root string, input io.Reader, output io.Writer) error {
	libPath, libraryPatched, _, err := findLibrary(root)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Navicat 17 Premium (EN) Crack (2026)\n\nlibcc.so found: %s\nSHA-256: %s ✅\n", libPath, originalSHA256)
	reader := bufio.NewReader(input)
	keyFile := cryptographicKeyPath()
	keyExists, keyUsable, err := inspectCryptographicKey(keyFile)
	if err != nil {
		return err
	}
	if keyExists {
		header += fmt.Sprintf("\nPreviously generated cryptographic key found: %s\n", keyFile)
		if !keyUsable {
			header += "Existing cryptographic key is invalid; regenerate it with option 2.\n"
		}
	}
	var keyPath string
	if keyUsable {
		keyPath = keyFile
	}
	patchCompleted := false
	var history []string
	terminal := isTerminalOutput(output)
	firstRender := true
	for {
		backupAvailable := regularFileExists(libPath + ".backup")
		renderInteractiveScreen(output, header, history, keyPath != "", keyExists, patchCompleted, backupAvailable, terminal && !firstRender)
		firstRender = false
		choice, err := promptLine(reader, output, "Select: ")
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var message string
		switch choice {
		case "1":
			if !backupAvailable {
				message = "[1] No libcc.so.backup is available."
				break
			}
			err = restoreLibraryFromBackup(libPath)
			if err == nil {
				libraryPatched = false
				patchCompleted = false
				message = "[1] Restore libcc.so backup\nRestored: " + libPath
			}
		case "2":
			err = saveNewPrivateKey(keyFile, keyExists)
			if err == nil {
				keyPath = keyFile
				keyExists = true
				patchCompleted = false
				message = "[2] Key generated: " + keyPath
				if libraryPatched {
					message += "\nRestore and patch libcc.so again to use this key."
				}
			}
		case "3":
			if keyPath == "" {
				message = missingCryptographicKeyMessage("3", keyExists)
				break
			}
			if libraryPatched {
				message = "[3] Restore libcc.so from backup before patching again."
				break
			}
			err = patchApplicationLibrary(libPath, keyPath)
			if err == nil {
				libraryPatched = true
				patchCompleted = true
				message = "[3] Patch libcc.so...\nlibcc.so.backup created\nlibcc.so successfully patched!"
			}
		case "4":
			if keyPath == "" {
				message = missingCryptographicKeyMessage("4", keyExists)
				break
			}
			var salt [3]byte
			_, err = rand.Read(salt[:])
			if err == nil {
				var serial string
				serial, err = generateSerial(17, "en", salt)
				if err == nil {
					message = "[4] License key: " + serial + "\nLaunch Navicat 17, enter the license key in the 'Registration...' window, then click Activate. Ignore the error, reopen 'Registration...' from the menu, and proceed to the next step."
				}
			}
		case "5":
			if !patchCompleted {
				message = "[5] Patch libcc.so with option 3 first."
				break
			}
			if terminal {
				renderInteractiveOutput(output, header, history)
			}
			var code, transcript string
			code, transcript, err = activateInteractive(reader, output, keyPath)
			if err == nil {
				message = transcript + "\n\nGenerated Activation Code:\n" + code
			}
		case "6":
			if terminal {
				renderInteractiveOutput(output, header, history)
			}
			fmt.Fprintln(output, "[6] Good Bye!")
			return nil
		default:
			message = "Choose 1, 2, 3, 4, 5 or 6."
		}
		if err != nil {
			message = fmt.Sprintf("[%s] Error: %v", choice, err)
		}
		if message != "" {
			history = append(history, message)
		}
	}
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
	fmt.Fprint(output, "\x1b[H\x1b[2J")
	fmt.Fprint(output, header)
	for _, message := range history {
		fmt.Fprintf(output, "\n%s\n", message)
	}
	fmt.Fprintln(output)
}

func renderInteractiveScreen(output io.Writer, header string, history []string, keyReady, keyExists, patched, backupAvailable, clear bool) {
	if clear {
		fmt.Fprint(output, "\x1b[H\x1b[2J")
	}
	fmt.Fprint(output, header)
	for _, message := range history {
		fmt.Fprintf(output, "\n%s\n", message)
	}
	fmt.Fprintln(output)
	printInteractiveMenu(output, keyReady, keyExists, patched, backupAvailable)
}

func printInteractiveMenu(output io.Writer, keyReady, keyExists, patched, backupAvailable bool) {
	useDim := isTerminalOutput(output)
	fmt.Fprintln(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	printMenuItem(output, "[1] Restore libcc.so backup", backupAvailable, useDim)
	if keyExists {
		fmt.Fprintln(output, "[2] Regenerate cryprographic key")
	} else {
		fmt.Fprintln(output, "[2] Generate cryprographic key")
	}
	printMenuItem(output, "[3] Patch libcc.so", keyReady, useDim)
	printMenuItem(output, "[4] Generate license key", keyReady, useDim)
	printMenuItem(output, "[5] Activate with activation request", patched, useDim)
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
		if decoded, decodeErr := base64.StdEncoding.DecodeString(request.String()); decodeErr == nil && len(decoded) == priv.Size() {
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
