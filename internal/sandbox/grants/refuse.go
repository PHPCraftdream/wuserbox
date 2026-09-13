package grants

import (
	"strings"

	"wuserbox/internal/policy/grant"
	"wuserbox/internal/policy/preset"
	"wuserbox/internal/policy/state"
)

// RefuseHomeFiles blocks the sandbox from changing the files already sitting
// in the profile root. It is only needed when the profile root was handed over
// on purpose, since that permission reaches those files as well.
//
// Files the sandbox was granted on purpose are left alone, together with the
// temporary files an agent writes beside them.
func RefuseHomeFiles(s *state.State) error {
	allowed := s.WritablePaths()
	for _, path := range preset.HomeFiles() {
		if isAllowed(path, allowed) {
			continue
		}
		if err := grant.Refuse(s.SID, path); err != nil {
			return err
		}
	}
	return nil
}

// isAllowed matches a granted file and the temporary names written beside it,
// such as the ".tmp.1234" companion of a config file being replaced.
func isAllowed(path string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(path, a) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(a)+".") {
			return true
		}
	}
	return false
}
