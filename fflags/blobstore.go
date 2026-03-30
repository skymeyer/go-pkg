package fflags

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/thomaspoignant/go-feature-flag/retriever"
	"github.com/thomaspoignant/go-feature-flag/retriever/fileretriever"
	"github.com/thomaspoignant/go-feature-flag/retriever/gcstorageretriever"
)

var (
	blobStoreMatcher = regexp.MustCompile(`^(gs)://([^/]+)/(.+.yaml)$|^(file)://(.+)/([^/]+.yaml)$`)
)

// NewBlobStore parses the input URI and returns a new BlobStore instance.
func NewBlobStore(in string) (*BlobStore, error) {
	// remove empty strings from the matches
	matches := slices.DeleteFunc(blobStoreMatcher.FindStringSubmatch(in), func(s string) bool {
		return strings.TrimSpace(s) == ""
	})
	if len(matches) != 4 {
		return nil, fmt.Errorf("invalid blobstore: %+q", matches)
	}
	return &BlobStore{
		kind:     matches[1],
		resource: matches[2],
		object:   matches[3],
	}, nil
}

// BlobStore holds the components of a feature flag storage location.
type BlobStore struct {
	kind     string
	resource string
	object   string
}

// Bucket returns the scheme and bucket or file path.
func (b *BlobStore) Bucket() string {
	return fmt.Sprintf("%s://%s", b.kind, b.resource)
}

// Object returns the filename or object key of the blob.
func (b *BlobStore) Object() string {
	return b.object
}

// Retriever creates a go-feature-flag Retriever based on the blob store kind.
func (b *BlobStore) Retriever() retriever.Retriever {
	switch b.kind {
	case "gs":
		return &gcstorageretriever.Retriever{
			Bucket: b.resource,
			Object: b.object,
		}
	case "file":
		return &fileretriever.Retriever{
			Path: b.resource + "/" + b.object,
		}
	default:
		return nil
	}
}
