package generate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"gopkg.in/yaml.v3"
)

// SourceFormat selects the decoder used to turn a provider response into
// CIDRs. Every built-in source declares its format explicitly so that CIDRs
// embedded in error pages, documentation examples or unrelated fields can
// never leak into the compiled dataset.
type SourceFormat string

const (
	// FormatLegacy is the backward-compatible full-body regex extractor. It
	// is only used for old config entries that do not declare a format and
	// still requires a 2xx response.
	FormatLegacy SourceFormat = ""
	// FormatText is a strict line-oriented CIDR list: every non-empty line
	// must parse as an IP prefix.
	FormatText SourceFormat = "text"
	// FormatCloudflare decodes api.cloudflare.com/client/v4/ips responses
	// and requires the business-level success flag to be true.
	FormatCloudflare SourceFormat = "cloudflare"
	// FormatIPInfo decodes ipinfo range widget responses ({ "ranges": [...] }).
	FormatIPInfo SourceFormat = "ipinfo"
	// FormatGcore decodes gcore public-ip-list responses.
	FormatGcore SourceFormat = "gcore"
	// FormatFastly decodes fastly public-ip-list responses.
	FormatFastly SourceFormat = "fastly"
	// FormatCloudFront decodes the cloudfront ip-list JSON responses.
	FormatCloudFront SourceFormat = "cloudfront"
	// FormatGoogle decodes goog.json/cloud.json prefix documents.
	FormatGoogle SourceFormat = "google"
	// FormatAWS decodes the AWS ip-ranges.json document.
	FormatAWS SourceFormat = "aws"
	// FormatOracle decodes the Oracle public_ip_ranges.json document.
	FormatOracle SourceFormat = "oracle"
	// FormatAzure first discovers the current ServiceTags_Public_ manifest
	// URL on the Azure download page and then decodes that manifest.
	FormatAzure SourceFormat = "azure"
	// FormatZscaler decodes the nested zscaler CENR document, reading only
	// the agreed "range" leaf fields.
	FormatZscaler SourceFormat = "zscaler"
	// FormatOffice365 decodes the office365 endpoints array, reading only
	// the agreed "ips" fields.
	FormatOffice365 SourceFormat = "office365"
)

// Source is a single provider URL together with the decoder that matches the
// response format the provider documents.
type Source struct {
	URL    string       `yaml:"url"`
	Format SourceFormat `yaml:"format"`
}

// Sources is a list of Source that also unmarshals the legacy plain-string
// URL form, keeping existing provider configs working. Plain strings default
// to FormatLegacy.
type Sources []Source

// UnmarshalYAML accepts both the legacy sequence of URL strings and the new
// sequence of {url, format} mappings.
func (s *Sources) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("urls: expected a sequence, got yaml kind %d", node.Kind)
	}
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			*s = append(*s, Source{URL: item.Value, Format: FormatLegacy})
		case yaml.MappingNode:
			var source Source
			if err := item.Decode(&source); err != nil {
				return err
			}
			if source.URL == "" {
				return errors.New("urls: entry is missing the \"url\" field")
			}
			*s = append(*s, source)
		default:
			return fmt.Errorf("urls: unsupported entry kind %d", item.Kind)
		}
	}
	return nil
}

// IsKnownSourceFormat reports whether format selects a registered decoder or
// the built-in Azure discovery flow. The empty legacy format is intentionally
// not considered known so shipped configs can be audited for explicit decoders.
func IsKnownSourceFormat(format SourceFormat) bool {
	if format == FormatAzure {
		return true
	}
	_, ok := sourceDecoders[format]
	return ok
}

// bodyDecoder turns a validated response body into CIDRs. Implementations
// only read the address fields agreed with the provider and return an error
// when the response structure does not match the documented format.
type bodyDecoder func(body []byte) ([]string, error)

var sourceDecoders = map[SourceFormat]bodyDecoder{
	FormatText:       decodeTextList,
	FormatCloudflare: decodeCloudflare,
	FormatIPInfo:     decodeIPInfoRanges,
	FormatGcore:      decodeGcore,
	FormatFastly:     decodeFastly,
	FormatCloudFront: decodeCloudFront,
	FormatGoogle:     decodeGooglePrefixes,
	FormatAWS:        decodeAWSRanges,
	FormatOracle:     decodeOracleRanges,
	FormatZscaler:    decodeZscalerRanges,
	FormatOffice365:  decodeOffice365Endpoints,
}

// userAgent mirrors the browser agent historically used by the generator.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"

func httpClientOrDefault(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

// httpGetBody performs a GET and rejects non-2xx responses before any body
// decoding happens, so an HTTP error page can never be treated as data even
// when it contains example CIDRs.
func httpGetBody(client *http.Client, target string) ([]byte, error) {
	client = httpClientOrDefault(client)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected status %s from %s", resp.Status, target)
	}
	return body, nil
}

// fetchSource downloads a source and decodes it with the explicitly selected
// format. Azure sources run discovery first and then decode the manifest with
// a separate decoder.
func fetchSource(client *http.Client, source Source) ([]string, error) {
	client = httpClientOrDefault(client)

	if source.Format == FormatAzure {
		return fetchAzureServiceTags(client, source.URL)
	}

	body, err := httpGetBody(client, source.URL)
	if err != nil {
		return nil, err
	}

	if source.Format == FormatLegacy {
		cidrs := cidrRegex.FindAllString(string(body), -1)
		if len(cidrs) == 0 {
			return nil, errNoCidrFound
		}
		return getValidateCidrs(cidrs), nil
	}

	decoder, ok := sourceDecoders[source.Format]
	if !ok {
		return nil, fmt.Errorf("unknown source format %q for %s", source.Format, source.URL)
	}
	cidrs, err := decoder(body)
	if err != nil {
		return nil, fmt.Errorf("%s decoder: %w", source.Format, err)
	}
	return cidrs, nil
}

// validPrefixes returns the candidates that parse as IP prefixes. Entries that
// do not parse (for example bare IPs in the ipinfo ranges widget) are dropped
// silently because they can never contribute a route; the caller must still
// reject an empty result.
func validPrefixes(candidates []string) []string {
	cidrs := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, err := netip.ParsePrefix(candidate); err == nil {
			cidrs = append(cidrs, candidate)
		}
	}
	return cidrs
}

// decodeTextList parses a strict line-oriented CIDR list.
func decodeTextList(body []byte) ([]string, error) {
	var cidrs []string
	for lineNo, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if _, err := netip.ParsePrefix(line); err != nil {
			return nil, fmt.Errorf("text list line %d %q is not a valid CIDR: %w", lineNo+1, line, err)
		}
		cidrs = append(cidrs, line)
	}
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeJSONObject requires body to be a JSON object and returns its raw
// top-level fields so decoders can enforce which keys must be present.
func decodeJSONObject(body []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("response is not a JSON object: %w", err)
	}
	return fields, nil
}

// decodeStringArray requires raw to be a JSON array of strings.
func decodeStringArray(raw json.RawMessage, field string) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("field %q must be an array of strings: %w", field, err)
	}
	return values, nil
}

// requireFields returns an error when any of fields is missing from the
// top-level object.
func requireFields(fields map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("missing required field %q", name)
		}
	}
	return nil
}

// decodeCloudflare enforces the cloudflare business success flag and only
// reads the agreed result.ipv4_cidrs / result.ipv6_cidrs fields.
func decodeCloudflare(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "success", "result"); err != nil {
		return nil, err
	}
	var success bool
	if err := json.Unmarshal(fields["success"], &success); err != nil {
		return nil, fmt.Errorf("field \"success\" must be a boolean: %w", err)
	}
	if !success {
		return nil, errors.New("business status success=false")
	}
	var result struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	}
	if err := json.Unmarshal(fields["result"], &result); err != nil {
		return nil, fmt.Errorf("field \"result\" has an unexpected structure: %w", err)
	}
	cidrs := validPrefixes(append(append([]string{}, result.IPv4CIDRs...), result.IPv6CIDRs...))
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeIPInfoRanges only reads the agreed top-level "ranges" array.
func decodeIPInfoRanges(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "ranges"); err != nil {
		return nil, err
	}
	ranges, err := decodeStringArray(fields["ranges"], "ranges")
	if err != nil {
		return nil, err
	}
	cidrs := validPrefixes(ranges)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeGcore only reads the agreed "addresses" / "addresses_v6" arrays.
func decodeGcore(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "addresses", "addresses_v6"); err != nil {
		return nil, err
	}
	ipv4, err := decodeStringArray(fields["addresses"], "addresses")
	if err != nil {
		return nil, err
	}
	ipv6, err := decodeStringArray(fields["addresses_v6"], "addresses_v6")
	if err != nil {
		return nil, err
	}
	cidrs := validPrefixes(append(append([]string{}, ipv4...), ipv6...))
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeFastly only reads the agreed "Addresses" / "ipv6_addresses" arrays.
func decodeFastly(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "Addresses", "ipv6_addresses"); err != nil {
		return nil, err
	}
	ipv4, err := decodeStringArray(fields["Addresses"], "Addresses")
	if err != nil {
		return nil, err
	}
	ipv6, err := decodeStringArray(fields["ipv6_addresses"], "ipv6_addresses")
	if err != nil {
		return nil, err
	}
	cidrs := validPrefixes(append(append([]string{}, ipv4...), ipv6...))
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeCloudFront only reads the two agreed CLOUDFRONT_* IP list arrays.
func decodeCloudFront(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "CLOUDFRONT_GLOBAL_IP_LIST", "CLOUDFRONT_REGIONAL_EDGE_IP_LIST"); err != nil {
		return nil, err
	}
	global, err := decodeStringArray(fields["CLOUDFRONT_GLOBAL_IP_LIST"], "CLOUDFRONT_GLOBAL_IP_LIST")
	if err != nil {
		return nil, err
	}
	regional, err := decodeStringArray(fields["CLOUDFRONT_REGIONAL_EDGE_IP_LIST"], "CLOUDFRONT_REGIONAL_EDGE_IP_LIST")
	if err != nil {
		return nil, err
	}
	cidrs := validPrefixes(append(append([]string{}, global...), regional...))
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// googlePrefixEntry matches one element of goog.json/cloud.json "prefixes".
type googlePrefixEntry struct {
	IPv4Prefix string `json:"ipv4Prefix"`
	IPv6Prefix string `json:"ipv6Prefix"`
}

// decodeGooglePrefixes requires a "prefixes" array of objects carrying
// ipv4Prefix/ipv6Prefix fields.
func decodeGooglePrefixes(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "prefixes"); err != nil {
		return nil, err
	}
	var entries []googlePrefixEntry
	if err := json.Unmarshal(fields["prefixes"], &entries); err != nil {
		return nil, fmt.Errorf("field \"prefixes\" must be an array of prefix objects: %w", err)
	}
	var candidates []string
	for _, entry := range entries {
		if entry.IPv4Prefix != "" {
			candidates = append(candidates, entry.IPv4Prefix)
		}
		if entry.IPv6Prefix != "" {
			candidates = append(candidates, entry.IPv6Prefix)
		}
	}
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeAWSRanges only reads prefixes[].ip_prefix and
// ipv6_prefixes[].ipv6_prefix from the AWS document.
func decodeAWSRanges(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "prefixes", "ipv6_prefixes"); err != nil {
		return nil, err
	}
	var ipv4Entries []struct {
		IPPrefix string `json:"ip_prefix"`
	}
	if err := json.Unmarshal(fields["prefixes"], &ipv4Entries); err != nil {
		return nil, fmt.Errorf("field \"prefixes\" must be an array of objects: %w", err)
	}
	var ipv6Entries []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
	}
	if err := json.Unmarshal(fields["ipv6_prefixes"], &ipv6Entries); err != nil {
		return nil, fmt.Errorf("field \"ipv6_prefixes\" must be an array of objects: %w", err)
	}
	candidates := make([]string, 0, len(ipv4Entries)+len(ipv6Entries))
	for _, entry := range ipv4Entries {
		candidates = append(candidates, entry.IPPrefix)
	}
	for _, entry := range ipv6Entries {
		candidates = append(candidates, entry.IPv6Prefix)
	}
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// decodeOracleRanges only reads regions[].cidrs[].cidr.
func decodeOracleRanges(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "regions"); err != nil {
		return nil, err
	}
	var regions []struct {
		CIDRs []struct {
			CIDR string `json:"cidr"`
		} `json:"cidrs"`
	}
	if err := json.Unmarshal(fields["regions"], &regions); err != nil {
		return nil, fmt.Errorf("field \"regions\" must be an array of region objects: %w", err)
	}
	var candidates []string
	for _, region := range regions {
		for _, item := range region.CIDRs {
			candidates = append(candidates, item.CIDR)
		}
	}
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// azureServiceTag matches the agreed ServiceTags manifest structure.
type azureServiceTag struct {
	Properties struct {
		AddressPrefixes []string `json:"addressPrefixes"`
	} `json:"properties"`
}

// decodeAzureServiceTags only reads values[].properties.addressPrefixes from
// a ServiceTags_Public_ manifest.
func decodeAzureServiceTags(body []byte) ([]string, error) {
	fields, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	if err := requireFields(fields, "values"); err != nil {
		return nil, err
	}
	var values []azureServiceTag
	if err := json.Unmarshal(fields["values"], &values); err != nil {
		return nil, fmt.Errorf("field \"values\" must be an array of service tag objects: %w", err)
	}
	var candidates []string
	for _, value := range values {
		candidates = append(candidates, value.Properties.AddressPrefixes...)
	}
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// discoverAzureServiceTagsURL fetches the Azure download confirmation page
// and returns the first ServiceTags_Public_ manifest link. Discovery is kept
// separate from manifest decoding: this function never extracts CIDRs.
func discoverAzureServiceTagsURL(client *http.Client, pageURL string) (string, error) {
	body, err := httpGetBody(client, pageURL)
	if err != nil {
		return "", fmt.Errorf("azure download page: %w", err)
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("azure download page is not parseable HTML: %w", err)
	}
	base, parseErr := url.Parse(pageURL)
	var manifest string
	doc.Find("a").Each(func(_ int, item *goquery.Selection) {
		if manifest != "" {
			return
		}
		href, ok := item.Attr("href")
		if ok && strings.Contains(href, "ServiceTags_Public_") {
			manifest = href
		}
	})
	if manifest == "" {
		return "", errors.New("azure: no ServiceTags_Public_ manifest link found on download page")
	}
	if parseErr == nil {
		if ref, err := url.Parse(manifest); err == nil {
			manifest = base.ResolveReference(ref).String()
		}
	}
	return manifest, nil
}

// fetchAzureServiceTags runs download-page discovery and then downloads and
// decodes the discovered manifest as two independently validated steps.
func fetchAzureServiceTags(client *http.Client, pageURL string) ([]string, error) {
	manifestURL, err := discoverAzureServiceTagsURL(client, pageURL)
	if err != nil {
		return nil, err
	}
	body, err := httpGetBody(client, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("azure manifest %s: %w", manifestURL, err)
	}
	cidrs, err := decodeAzureServiceTags(body)
	if err != nil {
		return nil, fmt.Errorf("azure manifest %s: %w", manifestURL, err)
	}
	return cidrs, nil
}

// decodeZscalerRanges walks the nested CENR document and reads only the
// agreed leaf "range" fields; other fields (gre, vpn, hostname, ...) are
// ignored even when they contain IP-looking strings.
func decodeZscalerRanges(body []byte) ([]string, error) {
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("response is not valid JSON: %w", err)
	}
	if _, ok := document.(map[string]any); !ok {
		return nil, errors.New("response root must be a JSON object")
	}
	var candidates []string
	collectZscalerRanges(document, &candidates)
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

func collectZscalerRanges(node any, out *[]string) {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "range" {
				if text, ok := child.(string); ok {
					*out = append(*out, text)
				}
				continue
			}
			collectZscalerRanges(child, out)
		}
	case []any:
		for _, child := range value {
			collectZscalerRanges(child, out)
		}
	}
}

// decodeOffice365Endpoints requires a top-level array and only reads the
// agreed "ips" field of each entry.
func decodeOffice365Endpoints(body []byte) ([]string, error) {
	var entries []struct {
		IPs []string `json:"ips"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("response must be a JSON array of endpoint objects: %w", err)
	}
	var candidates []string
	for _, entry := range entries {
		candidates = append(candidates, entry.IPs...)
	}
	cidrs := validPrefixes(candidates)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}
