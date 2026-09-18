// Tests for what a run writes into the record of what it copied: how the
// last run's list and this run's copy join, and which entry survives when
// both name the same place.

package setup

import (
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// TestAPartialCopyRecordsTheLimitsNowInForce is the guard on which entry
// wins when the record and this run's copy both name a path.
//
// agent had been copied whole, so the record held it bare. The rules file
// then gained exclude: [sessions/**], a later entry's copy failed, and the
// record went back to the union of the two lists -- with the bare entry
// first, and the record kept no exclusion. The next --no-ai run,
// which clears from the record without reading the rules file, deleted the
// sessions the exclusion had just been written to protect.
//
// The copied list carries the limits now in force -- copyEntries appends an
// entry before mirroring it -- so it is the one that has to win, and both
// directions of that choice are safe: a newer exclusion spares more when
// the entry is one day taken back, and a tighter depth clears less.
func TestAPartialCopyRecordsTheLimitsNowInForce(t *testing.T) {
	inForce := config.Entry{Path: "agent", Exclude: config.Masks([]string{"sessions/**"})}
	// still-listed stands for the entry the failed run never reached: it is
	// on the record and in the rules file, and the copy never got to it, so
	// only the record can speak for what it put in the profile.
	previously := []config.Entry{{Path: "agent"}, {Path: "still-listed"}}
	copied := []config.Entry{inForce}

	record := union(t.TempDir(), previously, copied, true)

	if len(record) != 2 {
		t.Fatalf("the record holds %v, want one entry for each path either list mentions", record)
	}
	var agent *config.Entry
	for i := range record {
		if record[i].Path == "agent" {
			agent = &record[i]
		}
	}
	if agent == nil {
		t.Fatalf("the union lost agent altogether: %v", record)
	}
	if len(agent.Exclude) != 1 || agent.Exclude[0].Pattern != "sessions/**" {
		t.Errorf("the recorded agent entry lost the exclusion now in force: %+v", *agent)
	}
}

// TestASuccessfulCopyRecordsExactlyWhatWasCopied pins the other branch, so
// the partial branch's precedence cannot leak into it: where the copy
// finished, the record is what the current list names and nothing else -- a
// path only the old record holds was already taken back by forget, and
// writing it down again would be the record claiming a copy that is not
// there.
func TestASuccessfulCopyRecordsExactlyWhatWasCopied(t *testing.T) {
	copied := []config.Entry{{Path: "agent"}}
	record := union(t.TempDir(), []config.Entry{{Path: "taken-back-already"}}, copied, false)
	if len(record) != 1 || record[0].Path != "agent" {
		t.Errorf("a finished copy recorded %v, want exactly what was copied", record)
	}
}

// TestAnEntryNamedByTwoSpellingsIsRecordedOnce is the record's own guard
// against the split that made forget orphan a copy: the rules file respelled
// an entry between runs, so the record and this run's copy name one place by
// two spellings. The volume-aware record keeps only the current entry, so the
// next --no-ai does not clear the same place twice with different limits.
func TestAnEntryNamedByTwoSpellingsIsRecordedOnce(t *testing.T) {
	inForce := config.Entry{Path: "./agent", Exclude: config.Masks([]string{"sessions/**"})}
	previously := []config.Entry{{Path: "agent"}, {Path: "still-listed"}}
	copied := []config.Entry{inForce}

	record := union(t.TempDir(), previously, copied, true)

	if len(record) != 2 {
		t.Fatalf("the record holds %v, want one entry for each place either list mentions", record)
	}
	var agent *config.Entry
	for i := range record {
		if record[i].Path == "./agent" {
			agent = &record[i]
		}
	}
	if agent == nil {
		t.Fatalf("the union lost agent altogether: %v", record)
	}
	if len(agent.Exclude) != 1 || agent.Exclude[0].Pattern != "sessions/**" {
		t.Errorf("the recorded agent entry lost the exclusion now in force: %+v", *agent)
	}
}
