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

// EvaluationRequest distinguishes explicit re-evaluation from automatic reuse.
type EvaluationRequest struct {
	AlertID int
	Force   bool
}

// Handler はジョブを処理する関数
type Handler func(ctx context.Context, job Job) error

// Queue はジョブキューとワーカープール
type Queue struct {
	ch          chan Job
	handlers    map[JobType]Handler
	wg          sync.WaitGroup
	workers     int
	ctx         context.Context
	cancel      context.CancelFunc
	jobWG       sync.WaitGroup
	admissionMu sync.RWMutex
	stopped     bool
	stopCh      chan struct{}
	stopOnce    sync.Once
}

// New はバッファサイズとワーカー数を指定してQueueを生成する
func New(bufferSize, workers int) *Queue {
	return &Queue{
		ch:       make(chan Job, bufferSize),
		handlers: make(map[JobType]Handler),
		workers:  workers,
		stopCh:   make(chan struct{}),
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
	q.stopOnce.Do(func() { close(q.stopCh) })
	q.admissionMu.Lock()
	q.stopped = true
	q.admissionMu.Unlock()
	if q.cancel != nil {
		q.cancel()
	}
	for {
		select {
		case <-q.ch:
			q.jobWG.Done()
		default:
			q.wg.Wait()
			q.jobWG.Wait()
			return
		}
	}
}

// Wait blocks until all jobs enqueued so far have completed.
func (q *Queue) Wait() { q.jobWG.Wait() }

// Enqueue はジョブをキューに追加する。満杯の場合は停止または空きが出るまで待機する。
func (q *Queue) Enqueue(job Job) {
	q.admissionMu.RLock()
	defer q.admissionMu.RUnlock()
	if q.stopped || (q.ctx != nil && q.ctx.Err() != nil) {
		return
	}
	var canceled <-chan struct{}
	if q.ctx != nil {
		canceled = q.ctx.Done()
	}
	q.jobWG.Add(1)
	select {
	case q.ch <- job:
	case <-q.stopCh:
		q.jobWG.Done()
	case <-canceled:
		q.jobWG.Done()
	}
}

// TryEnqueue admits a job without blocking a repository guard or queue worker.
func (q *Queue) TryEnqueue(job Job) bool {
	q.admissionMu.RLock()
	defer q.admissionMu.RUnlock()
	if q.stopped || (q.ctx != nil && q.ctx.Err() != nil) {
		return false
	}
	q.jobWG.Add(1)
	select {
	case q.ch <- job:
		return true
	default:
		q.jobWG.Done()
		return false
	}
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
				q.jobWG.Done()
				continue
			}
			if err := h(q.ctx, job); err != nil {
				slog.Error("ジョブ処理失敗", "type", job.Type, "worker", id, "error", err)
			}
			q.jobWG.Done()
		}
	}
}
