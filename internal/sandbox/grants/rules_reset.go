package grants

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// ResetProfile replaces only the copy list. The old rules are backed up whole.
func ResetProfile() (string, error) {
	var backup string
	err := lock.Hold(lock.Rules, func() error {
		path := config.Path()
		old, err := paths.ReadWhole(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("reading old rules: %w", err)
		}
		existed := err == nil
		rules, err := config.Load()
		if err != nil {
			return err
		}
		if existed {
			backup, err = backupRules(path, old)
			if err != nil {
				return fmt.Errorf("backing up old rules: %w", err)
			}
		}
		rules.Profile = preset.Profile()
		if err := rules.Save(); err != nil {
			if backup != "" {
				return fmt.Errorf("saving default profile rules (backup at %s): %w", backup, err)
			}
			return err
		}
		return nil
	})
	return backup, err
}

func backupRules(path string, content []byte) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for range 5 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", err
		}
		backup := fmt.Sprintf("%s.backup-%s-%x", path, stamp, suffix)
		if _, err := os.Lstat(backup); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if err := paths.Publish(backup, content, acl.Protect); err != nil {
			return "", err
		}
		return backup, nil
	}
	return "", fmt.Errorf("could not choose a unique backup name")
}
