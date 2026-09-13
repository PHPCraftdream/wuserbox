package config

import "github.com/PHPCraftdream/wuserbox/internal/policy/grant"

// Rule lists the extra directories one project directory gets.
type Rule struct {
	Dir string   `json:"dir"`
	RW  []string `json:"rw,omitempty"`
	RO  []string `json:"ro,omitempty"`
}

// Add records a path under the project rule and reports whether the file
// changed. A path already listed under the other kind is moved rather than
// listed twice: a directory that appears as both writable and readable would
// contradict itself, and the reader would silently keep the narrower of the
// two.
func (r *Rule) Add(path string, kind grant.Kind) bool {
	wanted, other := &r.RW, &r.RO
	if kind == grant.RO {
		wanted, other = &r.RO, &r.RW
	}
	moved := remove(other, path)
	for _, existing := range *wanted {
		if SamePath(existing, path) {
			return moved
		}
	}
	*wanted = append(*wanted, path)
	return true
}

// Kind reports how a path is listed, and whether it is listed at all.
func (r *Rule) Kind(path string) (grant.Kind, bool) {
	for _, listed := range r.RW {
		if SamePath(listed, path) {
			return grant.RW, true
		}
	}
	for _, listed := range r.RO {
		if SamePath(listed, path) {
			return grant.RO, true
		}
	}
	return "", false
}

// Remove drops a path from both lists, reporting whether anything changed.
func (r *Rule) Remove(path string) bool {
	writable := remove(&r.RW, path)
	readable := remove(&r.RO, path)
	return writable || readable
}

// remove drops every spelling of path from a list.
func remove(list *[]string, path string) bool {
	kept := (*list)[:0]
	changed := false
	for _, existing := range *list {
		if SamePath(existing, path) {
			changed = true
			continue
		}
		kept = append(kept, existing)
	}
	*list = kept
	return changed
}
