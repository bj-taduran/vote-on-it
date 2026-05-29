package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/audit"
)

// ── Mock ──────────────────────────────────────────────────────────────────────

type mockAuditWriter struct{ mock.Mock }

func (m *mockAuditWriter) PutAuditLog(ctx context.Context, item map[string]types.AttributeValue) error {
	args := m.Called(ctx, item)
	return args.Error(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestLog_WriteSucceeds(t *testing.T) {
	w := &mockAuditWriter{}
	w.On("PutAuditLog", mock.Anything, mock.Anything).Return(nil)

	logger := audit.New(w)
	// Should not panic; should call PutAuditLog once.
	logger.Log(context.Background(), "actor01", audit.ActionVoteCast, "PollID#poll-001", audit.OutcomeSuccess)

	w.AssertExpectations(t)
	w.AssertNumberOfCalls(t, "PutAuditLog", 1)
}

func TestLog_WriteFails_DoesNotPanic(t *testing.T) {
	w := &mockAuditWriter{}
	w.On("PutAuditLog", mock.Anything, mock.Anything).Return(errors.New("dynamo error"))

	logger := audit.New(w)
	// A write failure must not panic or propagate — the vote transaction already committed.
	logger.Log(context.Background(), "actor01", audit.ActionDuplicateVoteRejected, "PollID#poll-001", audit.OutcomeFailure)

	w.AssertExpectations(t)
}

func TestLog_ResultsRead(t *testing.T) {
	w := &mockAuditWriter{}
	w.On("PutAuditLog", mock.Anything, mock.Anything).Return(nil)

	logger := audit.New(w)
	logger.Log(context.Background(), "system", audit.ActionResultsRead, "PollID#poll-001", audit.OutcomeSuccess)

	w.AssertExpectations(t)
}
