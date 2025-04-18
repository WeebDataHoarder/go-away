package challenge

import (
	"context"
	"github.com/alphadose/haxmap"
	"sync/atomic"
)

type awaiterCallback func(result VerifyResult)

type Awaiter[K ~string | ~int64 | ~uint64] haxmap.Map[K, awaiterCallback]

func NewAwaiter[T ~string | ~int64 | ~uint64]() *Awaiter[T] {
	return (*Awaiter[T])(haxmap.New[T, awaiterCallback]())
}

func (a *Awaiter[T]) Await(key T, ctx context.Context) VerifyResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var result atomic.Int64

	a.m().Set(key, func(receivedResult VerifyResult) {
		result.Store(int64(receivedResult))
		cancel()
	})
	// cleanup
	defer a.m().Del(key)

	<-ctx.Done()

	return VerifyResult(result.Load())
}

func (a *Awaiter[T]) Solve(key T, result VerifyResult) {
	if f, ok := a.m().GetAndDel(key); ok && f != nil {
		f(result)
	}
}

func (a *Awaiter[T]) m() *haxmap.Map[T, awaiterCallback] {
	return (*haxmap.Map[T, awaiterCallback])(a)
}

func (a *Awaiter[T]) Close() error {
	return nil
}
