package enrichmentjournal

import (
	"reflect"
)

func validateTransition(previous *Checkpoint, next Checkpoint) error {
	if err := validateCheckpoint(next); err != nil {
		return err
	}
	if previous == nil {
		if next.Stage != Reserved {
			return invalid("initial stage")
		}
		return nil
	}
	if err := validateCheckpoint(*previous); err != nil {
		return err
	}
	a, b := canonicalCheckpoint(*previous), canonicalCheckpoint(next)
	if a.Version != b.Version || a.OperationID != b.OperationID || a.Request != b.Request {
		return invalid("changed operation binding")
	}
	if a.Stage == Reserved {
		if b.Stage != Begin && b.Stage != Returned {
			return invalid("reservation transition")
		}
		if b.Stage == Returned && b.Prepared != nil {
			return invalid("unreserved attempt")
		}
		return nil
	}
	if a.Prepared == nil || b.Prepared == nil || !reflect.DeepEqual(a.Prepared.Attempt, b.Prepared.Attempt) {
		return invalid("changed attempt")
	}
	// Scanning is complete before Begin; all subsequent stages preserve it.
	if a.Progress.RunID != b.Progress.RunID || a.Progress.Scanned != b.Progress.Scanned || a.Progress.Targets != b.Progress.Targets || a.Progress.ScanAfter != b.Progress.ScanAfter {
		return invalid("changed scan")
	}
	switch a.Stage {
	case Begin:
		if b.Stage != Fail && b.Stage != Complete && b.Stage != Returned {
			return invalid("begin transition")
		}
		if b.Stage == Returned && (b.Prepared.Failure != nil || b.Prepared.Completion != nil || b.Progress.Outcome != "pending" || (b.Progress.Code != "begin_unknown" && b.Progress.Code != "begin_replay" && b.Progress.Code != "begin_readback_unknown" && b.Progress.Code != "invalid_clock")) {
			return invalid("unprepared returned write")
		}
	case Fail, Complete:
		if b.Stage != Returned || !reflect.DeepEqual(a.Prepared, b.Prepared) || (b.Progress.Outcome == "pending" && ((a.Stage == Fail && b.Progress.Code != "failure_unknown") || (a.Stage == Complete && b.Progress.Code != "completion_unknown"))) {
			return invalid("changed prepared write")
		}
	case Returned:
		if a.Progress.Outcome != "pending" || b.Stage != Returned || (b.Progress.Outcome != "success" && b.Progress.Outcome != "failed") || !reflect.DeepEqual(a.Prepared, b.Prepared) {
			return invalid("returned transition")
		}
	default:
		return invalid("terminal transition")
	}
	return nil
}
