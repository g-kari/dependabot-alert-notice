package merger

import "context"

// Interface はPRマージ操作のインターフェース。
// web, slack パッケージはこのインターフェースに依存することでテスト可能になる。
type Interface interface {
	Approve(ctx context.Context, alertID int) error
	Reject(alertID int) error
	Merge(ctx context.Context, alertID int) error
}
