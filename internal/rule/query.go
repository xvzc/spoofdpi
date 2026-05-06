package rule

// MatchType identifies whether a Query targets a domain or an IP address.
type MatchType int

const (
	MatchTypeDomain MatchType = iota
	MatchTypeAddr
)

// Query is a lookup key passed to RuleSet.Search.
type Query struct {
	Type  MatchType
	Value string
}
