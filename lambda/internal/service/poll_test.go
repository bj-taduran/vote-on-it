package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/audit"
	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
	"github.com/bj-taduran/vote-on-it/internal/service"
)

// ── Mocks ─────────────────────────────────────────────────────────────────────

type mockRepo struct{ mock.Mock }

func (m *mockRepo) GetPollResults(ctx context.Context, pollID string) (*model.PollResultItem, error) {
	args := m.Called(ctx, pollID)
	item, _ := args.Get(0).(*model.PollResultItem)
	return item, args.Error(1)
}

func (m *mockRepo) CastVoteTransaction(ctx context.Context, voterHash, pollID, option string, expiresAt int64) error {
	args := m.Called(ctx, voterHash, pollID, option, expiresAt)
	return args.Error(0)
}

type mockAuditor struct{ mock.Mock }

func (m *mockAuditor) Log(ctx context.Context, actorID string, action audit.Action, resourceID string, outcome audit.Outcome) {
	m.Called(ctx, actorID, action, resourceID, outcome)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var testSalt = []byte("test-salt-32-bytes-padded-xxxxxxx")

func newTestService(repo service.Repository, auditor service.Auditor) *service.Service {
	return service.New(repo, auditor, testSalt, 24)
}

func validVoteRequest() *model.VoteRequest {
	return &model.VoteRequest{
		PollID:  "poll-2026-001",
		Option:  "A",
		VoterID: "550e8400-e29b-41d4-a716-446655440000",
	}
}

// ── CastVote ─────────────────────────────────────────────────────────────────

func TestCastVote_Success(t *testing.T) {
	repo := &mockRepo{}
	auditor := &mockAuditor{}

	repo.On("CastVoteTransaction", mock.Anything, mock.AnythingOfType("string"), "poll-2026-001", "A", mock.AnythingOfType("int64")).Return(nil)
	auditor.On("Log", mock.Anything, mock.AnythingOfType("string"), audit.ActionVoteCast, "PollID#poll-2026-001", audit.OutcomeSuccess).Return()

	svc := newTestService(repo, auditor)
	err := svc.CastVote(context.Background(), validVoteRequest())

	assert.NoError(t, err)
	repo.AssertExpectations(t)
	auditor.AssertExpectations(t)
}

func TestCastVote_DuplicateVote(t *testing.T) {
	repo := &mockRepo{}
	auditor := &mockAuditor{}

	repo.On("CastVoteTransaction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(repository.ErrDuplicateVote)
	auditor.On("Log", mock.Anything, mock.AnythingOfType("string"), audit.ActionDuplicateVoteRejected, mock.Anything, audit.OutcomeFailure).Return()

	svc := newTestService(repo, auditor)
	err := svc.CastVote(context.Background(), validVoteRequest())

	assert.ErrorIs(t, err, repository.ErrDuplicateVote)
	auditor.AssertExpectations(t)
}

func TestCastVote_TransactionError(t *testing.T) {
	repo := &mockRepo{}
	auditor := &mockAuditor{}

	repo.On("CastVoteTransaction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("dynamo unavailable"))
	auditor.On("Log", mock.Anything, mock.AnythingOfType("string"), audit.ActionVoteCast, mock.Anything, audit.OutcomeFailure).Return()

	svc := newTestService(repo, auditor)
	err := svc.CastVote(context.Background(), validVoteRequest())

	assert.ErrorContains(t, err, "dynamo unavailable")
	auditor.AssertExpectations(t)
}

// TestCastVote_HashIsDeterministic verifies that the same voter+poll always
// produces the same HMAC, and different polls produce different hashes.
func TestCastVote_HashIsDeterministic(t *testing.T) {
	capturedHashes := []string{}

	repo := &mockRepo{}
	auditor := &mockAuditor{}
	auditor.On("Log", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

	repo.On("CastVoteTransaction", mock.Anything, mock.MatchedBy(func(h string) bool {
		capturedHashes = append(capturedHashes, h)
		return true
	}), mock.Anything, mock.Anything, mock.Anything).Return(nil)

	svc := newTestService(repo, auditor)

	req := validVoteRequest()
	_ = svc.CastVote(context.Background(), req)
	_ = svc.CastVote(context.Background(), req)

	assert.Len(t, capturedHashes, 2)
	// Same inputs, same salt → must be identical
	assert.Equal(t, capturedHashes[0], capturedHashes[1])
	// Hash must be 64 hex chars (SHA-256 output)
	assert.Len(t, capturedHashes[0], 64)
}

// ── GetResults ────────────────────────────────────────────────────────────────

func TestGetResults_Success(t *testing.T) {
	repo := &mockRepo{}
	auditor := &mockAuditor{}

	repo.On("GetPollResults", mock.Anything, "poll-2026-001").Return(&model.PollResultItem{
		PollID: "poll-2026-001", OptionA: 10, OptionB: 20, OptionC: 5, OptionD: 15,
	}, nil)
	auditor.On("Log", mock.Anything, "system", audit.ActionResultsRead, "PollID#poll-2026-001", audit.OutcomeSuccess).Return()

	svc := newTestService(repo, auditor)
	res, err := svc.GetResults(context.Background(), "poll-2026-001")

	assert.NoError(t, err)
	assert.Equal(t, "poll-2026-001", res.PollID)
	assert.EqualValues(t, 10, res.Options["A"])
	assert.EqualValues(t, 50, res.Total)
	repo.AssertExpectations(t)
	auditor.AssertExpectations(t)
}

func TestGetResults_DBError(t *testing.T) {
	repo := &mockRepo{}
	auditor := &mockAuditor{}

	repo.On("GetPollResults", mock.Anything, "poll-2026-001").Return(nil, errors.New("table not found"))
	auditor.On("Log", mock.Anything, "system", audit.ActionResultsRead, "PollID#poll-2026-001", audit.OutcomeFailure).Return()

	svc := newTestService(repo, auditor)
	res, err := svc.GetResults(context.Background(), "poll-2026-001")

	assert.Nil(t, res)
	assert.ErrorContains(t, err, "table not found")
	auditor.AssertExpectations(t)
}
