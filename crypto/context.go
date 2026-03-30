package crypto

import (
	"context"
	"encoding/json"
)

type contextKey int

const (
	ctxAAD contextKey = iota
)

type AAD struct {
	Content string `json:"content"`
}

func AADFromContext(ctx context.Context) AAD {
	if aad, ok := ctx.Value(ctxAAD).(AAD); ok {
		return aad
	}
	return AAD{}
}

func AADJSONFromContext(ctx context.Context) []byte {
	b, _ := json.Marshal(AADFromContext(ctx))
	return b
}

func ContextWithAAD(ctx context.Context, aad AAD) context.Context {
	return context.WithValue(ctx, ctxAAD, aad)
}
