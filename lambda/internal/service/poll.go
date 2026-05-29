package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bj-taduran/vote-on-it/internal/audit"
	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
)

// Repository is the data-access capability required by Service.
type Repository interface {
	GetPollResults(ctx context.Context, pollID string) (*model.PollResultItem, error)
	CastVoteTransaction(ctx context.Context, voterHash, pollID, option string, expiresAt int64) error
}

// Auditor records state changes for SOC2 compliance.
type Auditor interface {
	Log(ctx context.Context, actorID string, action audit.Action, resourceID string, outcome audit.Outcome)
}

// Service owns all business logic. It has no knowledge of HTTP or DynamoDB
// wire formats — those belong to the handler and repository layers respectively.
type Service struct {
	repo     Repository
	auditor  Auditor
	salt     []byte
	ttlHours int64
}

// New returns a Service wired to the given dependencies.
func New(repo Repository, auditor Auditor, salt []byte, ttlHours int64) *Service {
	return &Service{repo: repo, auditor: auditor, salt: salt, ttlHours: ttlHours}
}

// CastVote pseudonymises the voter, runs the atomic dedup+increment transaction,
// and writes an audit record regardless of the outcome.
//
// The raw VoterID (client UUID) is never stored. Only its HMAC is persisted.
func (s *Service) CastVote(ctx context.Context, req *model.VoteRequest) error {
	voterHash := s.computeVoterHash(req.VoterID, req.PollID)
	actorID := voterHash[:8]
	resourceID := "PollID#" + req.PollID

	expiresAt := time.Now().UTC().Add(time.Duration(s.ttlHours) * time.Hour).Unix()

	err := s.repo.CastVoteTransaction(ctx, voterHash, req.PollID, req.Option, expiresAt)
	switch {
	case err == repository.ErrDuplicateVote:
		s.auditor.Log(ctx, actorID, audit.ActionDuplicateVoteRejected, resourceID, audit.OutcomeFailure)
		return repository.ErrDuplicateVote

	case err != nil:
		s.auditor.Log(ctx, actorID, audit.ActionVoteCast, resourceID, audit.OutcomeFailure)
		return fmt.Errorf("cast vote transaction: %w", err)

	default:
		s.auditor.Log(ctx, actorID, audit.ActionVoteCast, resourceID, audit.OutcomeSuccess)
		return nil
	}
}

// GetResults fetches current vote counts and audits the read.
func (s *Service) GetResults(ctx context.Context, pollID string) (*model.ResultsResponse, error) {
	resourceID := "PollID#" + pollID

	item, err := s.repo.GetPollResults(ctx, pollID)
	if err != nil {
		s.auditor.Log(ctx, "system", audit.ActionResultsRead, resourceID, audit.OutcomeFailure)
		return nil, fmt.Errorf("get poll results: %w", err)
	}

	s.auditor.Log(ctx, "system", audit.ActionResultsRead, resourceID, audit.OutcomeSuccess)

	total := item.OptionA + item.OptionB + item.OptionC + item.OptionD
	return &model.ResultsResponse{
		PollID: pollID,
		Options: map[string]int64{
			"A": item.OptionA,
			"B": item.OptionB,
			"C": item.OptionC,
			"D": item.OptionD,
		},
		Total: total,
	}, nil
}

// computeVoterHash returns HMAC-SHA256(voterID+pollID, salt) as a lowercase hex string.
// The input is the client-generated UUID — no IP address is processed at any point.
func (s *Service) computeVoterHash(voterID, pollID string) string {
	mac := hmac.New(sha256.New, s.salt)
	mac.Write([]byte(voterID + pollID))
	return hex.EncodeToString(mac.Sum(nil))
}
