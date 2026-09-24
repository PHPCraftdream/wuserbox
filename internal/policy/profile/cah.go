package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func rebaseCahCommands(root *os.Root, home string, copied []config.Entry) error {
	if !copiedEntry(copied, ".claude/cah-bin") || !copiedEntry(copied, ".claude/settings.json") {
		return nil
	}
	const settings = ".claude/settings.json"
	info, err := root.Lstat(settings)
	if err != nil {
		return fmt.Errorf("checking copied settings for cah commands: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("rebasing cah commands: copied settings are not a regular file")
	}
	source := filepath.Join(home, ".claude", "settings.json")
	content, err := os.ReadFile(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading source settings for cah commands: %w", err)
	}
	from := filepath.Join(home, ".claude", "cah-bin")
	to := filepath.Join(root.Name(), ".claude", "cah-bin")
	rewritten := rebaseCahPaths(content, from, to)
	if bytes.Equal(rewritten, content) {
		return nil
	}
	if err := replaceRootFile(root, settings, rewritten); err != nil {
		return fmt.Errorf("rebasing cah commands in copied settings: %w", err)
	}
	return nil
}

func copiedEntry(entries []config.Entry, name string) bool {
	for _, entry := range entries {
		if strings.EqualFold(filepath.ToSlash(entry.Path), name) {
			return true
		}
	}
	return false
}

func rebaseCahPaths(content []byte, from, to string) []byte {
	result := string(content)
	escapedSeparator := string(filepath.Separator) + string(filepath.Separator)
	for _, pair := range [][2]string{
		{filepath.ToSlash(from) + "/", filepath.ToSlash(to) + "/"},
		{strings.ReplaceAll(from, string(filepath.Separator), escapedSeparator) + escapedSeparator,
			strings.ReplaceAll(to, string(filepath.Separator), escapedSeparator) + escapedSeparator},
	} {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(pair[0]))
		result = re.ReplaceAllLiteralString(result, pair[1])
	}
	return []byte(result)
}

func replaceRootFile(root *os.Root, name string, content []byte) error {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := name + "." + hex.EncodeToString(random[:]) + ".tmp"
	out, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporary) }()
	if _, err := io.Copy(out, bytes.NewReader(content)); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return root.Rename(temporary, name)
}
