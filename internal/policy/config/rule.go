package config

// Rule lists the extra directories one project directory gets.
type Rule struct {
	Dir string   `json:"dir"`
	RW  []string `json:"rw,omitempty"`
	RO  []string `json:"ro,omitempty"`
}

// Add records path under the project rule, reporting whether it was new.
func (r *Rule) Add(path string, kind string) bool {
	list := &r.RW
	if kind == "ro" {
		list = &r.RO
	}
	for _, existing := range *list {
		if SamePath(existing, path) {
			return false
		}
	}
	*list = append(*list, path)
	return true
}

// Remove drops path from both lists, reporting whether anything changed.
func (r *Rule) Remove(path string) bool {
	changed := false
	for _, list := range []*[]string{&r.RW, &r.RO} {
		kept := (*list)[:0]
		for _, existing := range *list {
			if SamePath(existing, path) {
				changed = true
				continue
			}
			kept = append(kept, existing)
		}
		*list = kept
	}
	return changed
}
