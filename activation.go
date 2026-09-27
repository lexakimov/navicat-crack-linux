package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

func activateInteractive(reader *bufio.Reader, output io.Writer, keyPath string) (string, string, error) {
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return "", "", err
	}

	fmt.Fprintln(output, colorActionNumber("[5] Manual activation", isTerminalOutput(output)))

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

func makeActivationResponse(
	priv *rsa.PrivateKey,
	requestBase64, name, org string,
	when time.Time,
) (string, string, error) {
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
