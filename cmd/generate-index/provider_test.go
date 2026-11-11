package main

import (
	"os"
	"testing"

	"github.com/projectdiscovery/cdncheck/generate"
	"gopkg.in/yaml.v3"
)

// TestProviderConfigDeclaresExplicitFormats guards the invariant that every
// shipped provider URL selects its documented decoder. Regex fallback must
// never be reachable from the built-in config, so an HTTP error page cannot
// inject CIDRs into the compiled dataset.
func TestProviderConfigDeclaresExplicitFormats(t *testing.T) {
	raw, err := os.ReadFile("provider.yaml")
	if err != nil {
		t.Fatalf("read provider.yaml: %v", err)
	}

	var categories generate.Categories
	if err := yaml.Unmarshal(raw, &categories); err != nil {
		t.Fatalf("provider.yaml must decode with the Sources type: %v", err)
	}

	total := 0
	for name, category := range map[string]*generate.Category{
		"cdn":   categories.CDN,
		"waf":   categories.WAF,
		"cloud": categories.Cloud,
	} {
		if category == nil {
			t.Errorf("category %s missing from provider.yaml", name)
			continue
		}
		for provider, sources := range category.URLs {
			for _, source := range sources {
				total++
				if source.URL == "" {
					t.Errorf("%s/%s has an empty url entry", name, provider)
					continue
				}
				if source.Format == generate.FormatLegacy {
					t.Errorf("%s/%s (%s) must declare an explicit format instead of falling back to regex extraction", name, provider, source.URL)
					continue
				}
				if !generate.IsKnownSourceFormat(source.Format) {
					t.Errorf("%s/%s (%s) uses unknown format %q", name, provider, source.URL, source.Format)
				}
			}
		}
	}

	// 6 CDN sources, 3 WAF sources (cloudflare has two), 7 cloud sources.
	if total != 16 {
		t.Fatalf("expected 16 explicit URL sources in provider.yaml, got %d", total)
	}
}

// TestProviderConfigLegacyStringFormStillDecodes verifies backward
// compatibility with old configs that list plain URL strings.
func TestProviderConfigLegacyStringFormStillDecodes(t *testing.T) {
	const legacy = `
cdn:
  urls:
    custom:
    - https://example.com/ips.txt
`
	var categories generate.Categories
	if err := yaml.Unmarshal([]byte(legacy), &categories); err != nil {
		t.Fatalf("legacy plain-string url entries must still decode: %v", err)
	}
	sources := categories.CDN.URLs["custom"]
	if len(sources) != 1 || sources[0].URL != "https://example.com/ips.txt" || sources[0].Format != generate.FormatLegacy {
		t.Fatalf("legacy entry decoded incorrectly: %+v", sources)
	}
}
