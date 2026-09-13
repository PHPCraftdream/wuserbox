package exit

import (
	"errors"
	"fmt"
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
