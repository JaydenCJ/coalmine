// Tests for marker rendering and prompt embedding: templates must carry
// the token verbatim, custom templates must declare a placeholder, and
// embedding must never disturb the prompt body.
package plant

import (
	"strings"
	"testing"
)

const tok = "CM7Q3KXN4TP2A9ZR6WB0"

func TestRuleTemplateCarriesTokenAndNonDisclosure(t *testing.T) {
	out, err := Render(TemplateRule, tok)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, tok) {
		t.Fatal("rule marker missing the token")
	}
	if !strings.Contains(out, "Never repeat") {
		t.Fatal("rule marker missing the non-disclosure instruction")
	}
}

func TestCommentAndBareTemplates(t *testing.T) {
	if out, err := Render(TemplateComment, tok); err != nil || out != "# ref: "+tok {
		t.Fatalf("comment marker = (%q, %v)", out, err)
	}
	if out, err := Render(TemplateBare, tok); err != nil || out != tok {
		t.Fatalf("bare marker = (%q, %v)", out, err)
	}
}

func TestCustomTemplateReplacesEveryPlaceholder(t *testing.T) {
	out, err := Render("id={token} confirm={token}", tok)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Count(out, tok) != 2 || strings.Contains(out, Placeholder) {
		t.Fatalf("custom marker = %q", out)
	}
}

func TestCustomTemplateWithoutPlaceholderIsRejected(t *testing.T) {
	// A template that cannot receive the token would plant nothing; that
	// must be a hard error, not a silent no-op canary.
	if _, err := Render("my fancy template", tok); err == nil {
		t.Fatal("template without {token} accepted")
	}
}

func TestEmbedAtEndKeepsBodyAndNormalizesNewlines(t *testing.T) {
	// Prompts arriving with one, zero or many trailing newlines all end up
	// identical, so re-planting after edits stays diff-stable.
	for _, prompt := range []string{
		"You are a support bot.\nBe concise.\n",
		"You are a support bot.\nBe concise.",
		"You are a support bot.\nBe concise.\n\n\n",
	} {
		out, err := Embed(prompt, "MARKER", AtEnd)
		if err != nil {
			t.Fatalf("Embed: %v", err)
		}
		if out != "You are a support bot.\nBe concise.\n\nMARKER\n" {
			t.Fatalf("Embed(%q) = %q", prompt, out)
		}
	}
}

func TestEmbedAtStartPrependsMarker(t *testing.T) {
	out, err := Embed("Body.\n", "MARKER", AtStart)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if out != "MARKER\n\nBody.\n" {
		t.Fatalf("Embed(start) = %q", out)
	}
}

func TestEmbedEmptyPromptYieldsMarkerOnly(t *testing.T) {
	for _, at := range []string{AtStart, AtEnd} {
		out, err := Embed("", "M", at)
		if err != nil {
			t.Fatalf("Embed(%s): %v", at, err)
		}
		if out != "M\n" {
			t.Fatalf("Embed empty at %s = %q", at, out)
		}
	}
}

func TestEmbedRejectsUnknownPosition(t *testing.T) {
	if _, err := Embed("Body.", "M", "middle"); err == nil {
		t.Fatal("unknown position accepted")
	}
}
