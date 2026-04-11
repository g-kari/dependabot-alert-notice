package queue

import (
	"context"
	"log/slog"
	"sync"
)

// JobType はジョブの種別
type JobType string

const (
	// JobFetchAlerts はDependabotアラート取得ジョブ
	JobFetchAlerts JobType = "fetch_alerts"
	// JobEvaluateAlert はAI評価ジョブ
	JobEvaluateAlert JobType = "evaluate_alert"
)

// Job はキューに積むジョブ
type Job struct {
	Type    JobType
	Payload any
}

// Handler はジョブを処理する関数
type Handler func(ctx context.Context, job Job) error

// Queue はジョブキューとワーカープール
type Queue struct {
	ch       chan Job
	handlers map[JobType]Handler
	wg       sync.WaitGroup
	workers  int
	ctx      context.Context
	cancel   context.CancelFunc
}

// New はバッファサイズとワーカー数を指定してQueueを生成する
func New(bufferSize, workers int) *Queue {
	return &Queue{
		ch:       make(chan Job, bufferSize),
		handlers: make(map[JobType]Handler),
		workers:  workers,
	}
}

// Register はジョブ種別に対応するハンドラを登録する
func (q *Queue) Register(jobType JobType, h Handler) {
	q.handlers[jobType] = h
}

// Start はワーカーゴルーチンを起動する
func (q *Queue) Start(ctx context.Context) {
	q.ctx, q.cancel = context.WithCancel(ctx)
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(i)
	}
}

// Stop はワーカーを停止し、実行中のジョブが完了するまで待機する
func (q *Queue) Stop() {
	if q.cancel != nil {
		q.cancel()
	}
	q.wg.Wait()
}

// Enqueue はジョブをキューに追加する。キューが満杯の場合はブロックする
func (q *Queue) Enqueue(job Job) {
	q.ch <- job
}

// Len はキューに積まれているジョブ数を返す
func (q *Queue) Len() int {
	return len(q.ch)
}

func (q *Queue) worker(id int) {
	defer q.wg.Done()
	for {
		select {
		case <-q.ctx.Done():
			return
		case job, ok := <-q.ch:
			if !ok {
				return
			}
			h, found := q.handlers[job.Type]
			if !found {
				slog.Warn("未知のジョブタイプ", "type", job.Type)
				continue
			}
			if err := h(q.ctx, job); err != nil {
				slog.Error("ジョブ処理失敗", "type", job.Type, "worker", id, "error", err)
			}
		}
	}
}
