package generate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// spoofedErrorPage is an HTTP error body that deliberately contains valid
// example CIDRs. A regex-over-body extractor would accept these as data.
const spoofedErrorPage = `<!doctype html>
<html><body>
<h1>500 Internal Server Error</h1>
<p>The requested range is unavailable. Example network 192.0.2.0/24 and 2001:db8::/32 were not updated.</p>
</body></html>`

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func assertCIDRs(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(sortedCopy(got), sortedCopy(want)) {
		t.Fatalf("cidrs = %v, want %v", got, want)
	}
}

func TestSources_UnmarshalYAMLLegacyAndExplicitFormats(t *testing.T) {
	const config = `
urls:
  legacy:
    - https://example.com/ips.txt
  explicit:
    - url: https://example.com/manifest.json
      format: cloudflare
  mixed:
    - https://example.com/a.txt
    - url: https://example.com/b.json
      format: google
`
	var cat struct {
		URLs map[string]Sources `yaml:"urls"`
	}
	if err := yaml.Unmarshal([]byte(config), &cat); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := cat.URLs["legacy"]; len(got) != 1 || got[0].URL != "https://example.com/ips.txt" || got[0].Format != FormatLegacy {
		t.Fatalf("legacy entry = %+v", got)
	}
	if got := cat.URLs["explicit"]; len(got) != 1 || got[0].Format != FormatCloudflare {
		t.Fatalf("explicit entry = %+v", got)
	}
	got := cat.URLs["mixed"]
	if len(got) != 2 || got[0].Format != FormatLegacy || got[1].Format != FormatGoogle {
		t.Fatalf("mixed entry = %+v", got)
	}
}

func TestSources_UnmarshalYAMLRejectsBadShapes(t *testing.T) {
	for name, config := range map[string]string{
		"mapping missing url": "urls:\n  p:\n    - format: text\n",
		"non-sequence":        "urls:\n  p: not-a-sequence\n",
	} {
		t.Run(name, func(t *testing.T) {
			var cat struct {
				URLs map[string]Sources `yaml:"urls"`
			}
			if err := yaml.Unmarshal([]byte(config), &cat); err == nil {
				t.Fatalf("expected decode error for %s", name)
			}
		})
	}
}

func TestDecodeTextList(t *testing.T) {
	t.Run("dual stack strict list", func(t *testing.T) {
		body := []byte("10.0.0.0/24\n\n  2001:db8::/32  \n")
		got, err := decodeTextList(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCIDRs(t, got, []string{"10.0.0.0/24", "2001:db8::/32"})
	})
	t.Run("rejects non-CIDR line", func(t *testing.T) {
		if _, err := decodeTextList([]byte("10.0.0.0/24\nnot-a-cidr\n")); err == nil {
			t.Fatal("expected error for non-CIDR line")
		}
	})
	t.Run("rejects spoofed html error page even with 200", func(t *testing.T) {
		if _, err := decodeTextList([]byte(spoofedErrorPage)); err == nil {
			t.Fatal("spoofed HTML error page must not decode as a text list")
		}
	})
	t.Run("empty body", func(t *testing.T) {
		if _, err := decodeTextList([]byte("\n \n")); !errors.Is(err, errNoCidrFound) {
			t.Fatalf("expected errNoCidrFound, got %v", err)
		}
	})
}

func TestFetchSource_RejectsErrorStatusWithDecoyCIDRs(t *testing.T) {
	servers := map[SourceFormat]*httptest.Server{}
	formats := []SourceFormat{FormatText, FormatCloudflare, FormatGcore, FormatFastly, FormatCloudFront, FormatGoogle, FormatAWS, FormatOracle, FormatZscaler, FormatOffice365, FormatIPInfo}
	for _, format := range formats {
		format := format
		servers[format] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(spoofedErrorPage))
		}))
	}
	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			cidrs, err := fetchSource(nil, Source{URL: servers[format].URL, Format: format})
			if err == nil {
				t.Fatalf("expected status error, got cidrs %v", cidrs)
			}
			if len(cidrs) != 0 {
				t.Fatalf("error response must not yield cidrs, got %v", cidrs)
			}
		})
	}
}

func TestFetchSource_LegacyRequires2xxButStillExtractsOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("error: see 192.0.2.0/24 for an example range"))
	}))
	defer srv.Close()
	if cidrs, err := fetchSource(nil, Source{URL: srv.URL}); err == nil || len(cidrs) != 0 {
		t.Fatalf("legacy format must reject non-2xx, got cidrs=%v err=%v", cidrs, err)
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("prefix 10.0.0.0/24 end"))
	}))
	defer ok.Close()
	cidrs, err := fetchSource(nil, Source{URL: ok.URL})
	if err != nil {
		t.Fatalf("legacy 200 extraction should still work: %v", err)
	}
	assertCIDRs(t, cidrs, []string{"10.0.0.0/24"})
}

func TestFetchSource_UnknownFormatErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/24"))
	}))
	defer srv.Close()
	if _, err := fetchSource(nil, Source{URL: srv.URL, Format: "nope"}); err == nil {
		t.Fatal("unknown format must error instead of silently accepting data")
	}
}

func TestDecodeCloudflare(t *testing.T) {
	t.Run("dual stack happy path ignores unrelated fields", func(t *testing.T) {
		body := []byte(`{
			"success": true,
			"errors": [],
			"messages": [],
			"result": {
				"ipv4_cidrs": ["10.0.0.0/24"],
				"ipv6_cidrs": ["2001:db8::/32"],
				"etag": "abc"
			},
			"examples": ["192.0.2.0/24"]
		}`)
		got, err := decodeCloudflare(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCIDRs(t, got, []string{"10.0.0.0/24", "2001:db8::/32"})
	})
	t.Run("business failure rejected despite decoy ranges", func(t *testing.T) {
		body := []byte(`{
			"success": false,
			"errors": [{"code": 1, "message": "rate limited"}],
			"result": {"ipv4_cidrs": ["192.0.2.0/24"], "ipv6_cidrs": []}
		}`)
		if _, err := decodeCloudflare(body); err == nil {
			t.Fatal("success=false response must be rejected")
		}
	})
	t.Run("missing result rejected", func(t *testing.T) {
		if _, err := decodeCloudflare([]byte(`{"success": true}`)); err == nil {
			t.Fatal("response without result must be rejected")
		}
	})
	t.Run("spoofed html page rejected", func(t *testing.T) {
		if _, err := decodeCloudflare([]byte(spoofedErrorPage)); err == nil {
			t.Fatal("HTML error page must not decode as cloudflare JSON")
		}
	})
}

func TestJSONDecoders_DualStackAndFieldScoping(t *testing.T) {
	decoy := `"decoy": ["192.0.2.0/24", "2001:db8:ffff::/48"]`
	tests := []struct {
		name   string
		format SourceFormat
		body   string
		want   []string
	}{
		{
			name:   "gcore",
			format: FormatGcore,
			body:   `{"addresses": ["10.0.0.0/24"], "addresses_v6": ["2001:db8::/32"], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "fastly",
			format: FormatFastly,
			body:   `{"Addresses": ["10.0.0.0/24"], "ipv6_addresses": ["2001:db8::/32"], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "cloudfront",
			format: FormatCloudFront,
			body:   `{"CLOUDFRONT_GLOBAL_IP_LIST": ["10.0.0.0/24"], "CLOUDFRONT_REGIONAL_EDGE_IP_LIST": ["10.1.0.0/24"], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "10.1.0.0/24"},
		},
		{
			name:   "google",
			format: FormatGoogle,
			body:   `{"prefixes": [{"ipv4Prefix": "10.0.0.0/24"}, {"ipv6Prefix": "2001:db8::/32"}], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "aws",
			format: FormatAWS,
			body:   `{"prefixes": [{"ip_prefix": "10.0.0.0/24", "region": "us-east-1"}], "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/32"}], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "oracle",
			format: FormatOracle,
			body:   `{"regions": [{"region": "us-ashburn-1", "cidrs": [{"cid": "x", "cidr": "10.0.0.0/24"}, {"cidr": "2001:db8::/32"}]}], ` + decoy + `}`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "office365",
			format: FormatOffice365,
			body:   `[{"id": 1, "service": "Exchange", "ips": ["10.0.0.0/24", "2001:db8::/32"], "urls": ["example.com"]}]`,
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := sourceDecoders[tt.format]
			got, err := decoder([]byte(tt.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertCIDRs(t, got, tt.want)
		})
	}
}

func TestDecodeIPInfoRanges_FiltersBareIPsAndIgnoresSiblings(t *testing.T) {
	body := []byte(`{
		"domain": "cloudflare.com",
		"num_ranges": 3,
		"ranges": ["10.0.0.0/24", "104.30.162.254", "2001:db8::/32"],
		"decoy": ["192.0.2.0/24"]
	}`)
	got, err := decodeIPInfoRanges(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCIDRs(t, got, []string{"10.0.0.0/24", "2001:db8::/32"})
}

func TestDecodeZscalerRanges_OnlyReadsRangeLeafs(t *testing.T) {
	// gre/vpn carry bare IPs and must never be collected; a decoy object must
	// not contribute anything either.
	body := []byte(`{
		"zscaler.net": {
			"continent : EMEA": {
				"city : Amsterdam II": [
					{"range": "137.31.30.0/23", "vpn": "", "gre": "165.225.240.12", "hostname": "ams.sme.zscaler.net"},
					{"range": "2a03:eec0:3900::/40", "vpn": "ams-vpn.zscaler.net", "gre": ""}
				]
			},
			"decoy": [{"range": "192.0.2.0/24", "gre": "198.51.100.1"}]
		}
	}`)
	got, err := decodeZscalerRanges(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCIDRs(t, got, []string{"137.31.30.0/23", "2a03:eec0:3900::/40", "192.0.2.0/24"})

	if _, err := decodeZscalerRanges([]byte(`[{"range":"10.0.0.0/24"}]`)); err == nil {
		t.Fatal("array root must be rejected as a structural change")
	}
}

func TestJSONDecoders_RejectStructuralChanges(t *testing.T) {
	cases := []struct {
		name   string
		format SourceFormat
		body   string
	}{
		{"google prefixes became strings", FormatGoogle, `{"prefixes": ["10.0.0.0/24"]}`},
		{"google missing prefixes", FormatGoogle, `{"creationToken": "x"}`},
		{"aws missing ipv6_prefixes", FormatAWS, `{"prefixes": [{"ip_prefix": "10.0.0.0/24"}]}`},
		{"aws prefixes became strings", FormatAWS, `{"prefixes": ["10.0.0.0/24"], "ipv6_prefixes": []}`},
		{"oracle missing regions", FormatOracle, `{"last_updated_time": "x"}`},
		{"office365 root became object", FormatOffice365, `{"ips": ["10.0.0.0/24"]}`},
		{"cloudfront missing lists", FormatCloudFront, `{"other": ["10.0.0.0/24"]}`},
		{"gcore missing addresses", FormatGcore, `{"addresses_v6": ["2001:db8::/32"]}`},
		{"ipinfo missing ranges", FormatIPInfo, `{"domain": "x"}`},
		{"azure manifest missing values", FormatAzure, `{"changeNumber": 1}`},
		{"azure values became strings", FormatAzure, `{"values": ["10.0.0.0/24"]}`},
		{"plain text fed to json decoder", FormatGoogle, `10.0.0.0/24`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.format == FormatAzure {
				if _, err := decodeAzureServiceTags([]byte(tt.body)); err == nil {
					t.Fatal("expected structural error")
				}
				return
			}
			decoder, ok := sourceDecoders[tt.format]
			if !ok {
				t.Fatalf("no decoder for %s", tt.format)
			}
			if _, err := decoder([]byte(tt.body)); err == nil {
				t.Fatal("expected structural error")
			}
		})
	}
}

func TestAzureDiscoveryAndManifestDecoding(t *testing.T) {
	manifest := `{
		"changeNumber": 42,
		"cloud": "Public",
		"values": [
			{"name": "AzureCloud", "id": "1", "properties": {"addressPrefixes": ["10.0.0.0/24", "2001:db8::/32"]}},
			{"name": "Ignore", "id": "2", "properties": {"addressPrefixes": []}}
		],
		"decoy": ["192.0.2.0/24"]
	}`

	t.Run("discovery finds absolute link and manifest decodes", func(t *testing.T) {
		var manifestURL string
		manifestSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(manifest))
		}))
		defer manifestSrv.Close()
		manifestURL = manifestSrv.URL + "/ServiceTags_Public_20260101.json"

		pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html><body><a href="` + manifestURL + `">download</a></body></html>`))
		}))
		defer pageSrv.Close()

		got, err := fetchSource(nil, Source{URL: pageSrv.URL, Format: FormatAzure})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCIDRs(t, got, []string{"10.0.0.0/24", "2001:db8::/32"})
	})

	t.Run("discovery resolves relative links", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/page":
				_, _ = w.Write([]byte(`<a href="/ServiceTags_Public_test.json">manifest</a>`))
			case "/ServiceTags_Public_test.json":
				_, _ = w.Write([]byte(manifest))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		url, err := discoverAzureServiceTagsURL(nil, srv.URL+"/page")
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		if !strings.HasSuffix(url, "/ServiceTags_Public_test.json") {
			t.Fatalf("unexpected manifest url %q", url)
		}
		got, err := fetchSource(nil, Source{URL: srv.URL + "/page", Format: FormatAzure})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCIDRs(t, got, []string{"10.0.0.0/24", "2001:db8::/32"})
	})

	t.Run("page without manifest link errors", func(t *testing.T) {
		pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html><body><a href="/other.json">other</a></body></html>`))
		}))
		defer pageSrv.Close()
		if _, err := fetchSource(nil, Source{URL: pageSrv.URL, Format: FormatAzure}); err == nil {
			t.Fatal("page without ServiceTags link must fail discovery")
		}
	})

	t.Run("manifest error page with decoy cidrs rejected", func(t *testing.T) {
		manifestSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(spoofedErrorPage))
		}))
		defer manifestSrv.Close()

		pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<a href="` + manifestSrv.URL + `/ServiceTags_Public_bad.json">manifest</a>`))
		}))
		defer pageSrv.Close()

		cidrs, err := fetchSource(nil, Source{URL: pageSrv.URL, Format: FormatAzure})
		if err == nil {
			t.Fatalf("manifest error page must be rejected, got cidrs %v", cidrs)
		}
		if len(cidrs) != 0 {
			t.Fatalf("no cidrs may come back from a failed manifest, got %v", cidrs)
		}
	})

	t.Run("download page error status rejected", func(t *testing.T) {
		pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(spoofedErrorPage))
		}))
		defer pageSrv.Close()
		if _, err := fetchSource(nil, Source{URL: pageSrv.URL, Format: FormatAzure}); err == nil {
			t.Fatal("download page error status must be rejected before discovery")
		}
	})
}

func TestFetchInputItem_SpoofedErrorsCannotChangeClassification(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {"ipv4_cidrs": ["10.0.0.0/24"], "ipv6_cidrs": ["2001:db8::/32"]},
			"examples": ["192.0.2.0/24"]
		}`))
	}))
	defer good.Close()

	spoofed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(spoofedErrorPage))
	}))
	defer spoofed.Close()

	cat := &Category{
		URLs: map[string]Sources{
			"good": {{URL: good.URL, Format: FormatCloudflare}},
			"evil": {{URL: spoofed.URL, Format: FormatCloudflare}},
		},
	}
	data := map[string][]string{}
	err := cat.fetchInputItem(&Options{}, data)
	if err == nil || !strings.Contains(err.Error(), "evil") {
		t.Fatalf("spoofed source must surface a joined error, got %v", err)
	}
	assertCIDRs(t, data["good"], []string{"10.0.0.0/24", "2001:db8::/32"})
	if cidrs, ok := data["evil"]; ok {
		t.Fatalf("spoofed source must not populate any cidrs, got %v", cidrs)
	}
}

func TestFetchInputItem_SoftErrorPageWith200RejectedByTextFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(spoofedErrorPage))
	}))
	defer srv.Close()

	cat := &Category{
		URLs: map[string]Sources{
			"evil": {{URL: srv.URL, Format: FormatText}},
		},
	}
	data := map[string][]string{}
	if err := cat.fetchInputItem(&Options{}, data); err == nil {
		t.Fatal("soft error page must be rejected by the strict text decoder")
	}
	if cidrs, ok := data["evil"]; ok {
		t.Fatalf("error page cidrs must never enter the dataset, got %v", cidrs)
	}
}
