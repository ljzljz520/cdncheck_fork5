package generate

// Categories contains various cdn, waf, cloud and fqdn operators
type Categories struct {
	// CDN contains a list of inputs for CDN cidrs
	CDN *Category `yaml:"cdn"`
	// WAF contains a list of inputs for WAF cidrs
	WAF *Category `yaml:"waf"`
	// Cloud contains a list of inputs for Cloud cidrs
	Cloud  *Category `yaml:"cloud"`
	Common *Category `yaml:"common"`
}

// Category contains configuration for a specific category
type Category struct {
	// URLs contains a list of source URLs for CIDR lists. Each source
	// explicitly selects the response decoder through its Format field;
	// legacy plain-string URL entries are still accepted and fall back to
	// the regex extractor.
	URLs map[string]Sources `yaml:"urls"`
	// ASN contains ASN numbers for an Input item
	ASN map[string][]string `yaml:"asn"`
	// CIDR contains a list of CIDRs for Input item
	//
	// CIDR is generated using generate-index tool which is then
	// used for checking the provided IP for each input type.
	CIDR map[string][]string `yaml:"cidr"`
	// FQDN contains public suffixes for major cloud operators
	FQDN map[string][]string `yaml:"fqdn"`
}
