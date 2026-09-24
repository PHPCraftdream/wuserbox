package setup

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
)

func TestReInitRejectsArguments(t *testing.T) {
	err := ReInit([]string{"unexpected"})
	if exit.Of(err) != exit.Usage || !strings.Contains(err.Error(), "--re-init") {
		t.Errorf("unexpected arguments returned %v", err)
	}
}
