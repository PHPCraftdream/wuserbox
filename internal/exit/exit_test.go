package exit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOfReadsTheCarriedCode(t *testing.T) {
	err := Errorf(Denied, "writing to %s", `C:\x`)
	if got := Of(err); got != Denied {
		t.Errorf("got %v, want %v", got, Denied)
	}
	if err.Error() != `writing to C:\x` {
		t.Errorf("message is %q", err.Error())
	}
}

func TestOfFindsACodeThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("while preparing: %w", Errorf(BadConfig, "broken"))
	if got := Of(wrapped); got != BadConfig {
		t.Errorf("got %v, want %v", got, BadConfig)
	}
}

func TestOfFallsBackToTheGeneralFailure(t *testing.T) {
	if got := Of(errors.New("something")); got != Failed {
		t.Errorf("got %v, want %v", got, Failed)
	}
}

func TestOfTreatsNoErrorAsSuccess(t *testing.T) {
	if got := Of(nil); got != OK {
		t.Errorf("got %v, want %v", got, OK)
	}
}

func TestEveryCodeIsNamedAndDistinct(t *testing.T) {
	codes := []Code{OK, Failed, Usage, Denied, NeedsElevation, BadConfig, NotFound}
	seenNames := map[string]bool{}
	seenValues := map[Code]bool{}
	for _, code := range codes {
		name := code.String()
		if name == "unknown" {
			t.Errorf("code %d has no name", code)
		}
		if seenNames[name] {
			t.Errorf("two codes share the name %q", name)
		}
		if seenValues[code] {
			t.Errorf("two codes share the value %d", code)
		}
		seenNames[name] = true
		seenValues[code] = true
	}
	if Code(99).String() != "unknown" {
		t.Error("an unlisted code should not be named")
	}
}

// TestReportAnswersInTheShapeThatWasAskedFor covers the part of the command
// line contract that was left unfinished: a command called with --json
// answered in JSON when it worked and in prose when it failed, so anything
// reading the output had to handle two shapes.
func TestReportAnswersInTheShapeThatWasAskedFor(t *testing.T) {
	failure := Errorf(Denied, "no permission for %s", `C:\tools`)

	var plain bytes.Buffer
	Report(&plain, failure, false)
	if !strings.HasPrefix(plain.String(), "wuserbox: ") {
		t.Errorf("the plain report does not look as it did: %q", plain.String())
	}

	var encoded bytes.Buffer
	Report(&encoded, failure, true)
	var back struct {
		Error  string `json:"error"`
		Code   int    `json:"code"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(encoded.Bytes(), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v (%q)", err, encoded.String())
	}
	if back.Error != failure.Error() {
		t.Errorf("the message came back as %q", back.Error)
	}
	if back.Code != int(Denied) || back.Status != Denied.String() {
		t.Errorf("the code came back as %d/%q", back.Code, back.Status)
	}
}

func TestReportSaysNothingAboutSuccess(t *testing.T) {
	var out bytes.Buffer
	Report(&out, nil, true)
	if out.Len() != 0 {
		t.Errorf("a report was written for a command that worked: %q", out.String())
	}
}

func TestJSONAskedReadsTheCommandLine(t *testing.T) {
	for _, asking := range [][]string{
		{"--json"}, {"grant", `C:\tools`, "--json"}, {"--json=true"}, {"-json"},
	} {
		if !JSONAsked(asking) {
			t.Errorf("%v asks for JSON", asking)
		}
	}
	for _, not := range [][]string{
		{}, {"grant", `C:\tools`}, {"--json=false"}, {"--jsonish"},
		// After the separator the flags belong to the program being run.
		{"run", "--", "node", "--json"},
	} {
		if JSONAsked(not) {
			t.Errorf("%v does not ask wuserbox for JSON", not)
		}
	}
}
