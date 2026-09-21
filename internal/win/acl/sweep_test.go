package acl

import "testing"

func TestUnderSkippedUsesFilesystemSpelling(t *testing.T) {
	root := `C:\tree\K`
	if !underSkipped(root+`\child`, root) {
		t.Fatal("a descendant of a skipped directory was not recognized")
	}
	if underSkipped(`C:\tree\`+"K"+`\child`, root) {
		t.Fatal("a Unicode-distinct sibling was treated as a skipped descendant")
	}
	if underSkipped(root+`2`, root) {
		t.Fatal("a name with the skipped directory as a prefix was treated as a descendant")
	}
}
