package feed

// Parse normalizes an RSS or Atom XML document without performing network I/O.
func Parse(data []byte, maxItems int) ([]Item, error) { return parse(data, maxItems) }
