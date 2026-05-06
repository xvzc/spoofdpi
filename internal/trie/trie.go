package trie

// Trie is a generic key-value search tree.
// Set stores a value under the given key; Search returns the best match.
type Trie[T any] interface {
	Add(key string, value T) error
	Search(key string) (T, bool)
}
