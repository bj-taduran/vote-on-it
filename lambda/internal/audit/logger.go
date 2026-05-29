package audit

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

// Action is a valid SOC2 audit event type.
type Action string

const (
	ActionVoteCast              Action = "VOTE_CAST"
	ActionResultsRead           Action = "RESULTS_READ"
	ActionDuplicateVoteRejected Action = "DUPLICATE_VOTE_REJECTED"
)

// Outcome is the result of an audited action.
type Outcome string

const (
	OutcomeSuccess Outcome = "SUCCESS"
	OutcomeFailure Outcome = "FAILURE"
)

// AuditWriter is the repository capability required by Logger.
// Defined here so the audit package has no import dependency on repository.
type AuditWriter interface {
	PutAuditLog(ctx context.Context, item map[string]types.AttributeValue) error
}

// Logger writes structured audit records to DynamoDB and mirrors each event
// as a structured CloudWatch log line.
type Logger struct {
	repo AuditWriter
}

// New returns a Logger backed by the given AuditWriter.
func New(repo AuditWriter) *Logger {
	return &Logger{repo: repo}
}

// Log writes an immutable audit record.
// A DynamoDB write failure is logged but never fatal — the main state change
// (the vote transaction) has already committed and must not be rolled back.
//
// actorID must already be pseudonymised (e.g. VoterHash[:8] or "system").
// Raw IP addresses must never be passed here.
func (l *Logger) Log(ctx context.Context, actorID string, action Action, resourceID string, outcome Outcome) {
	now := time.Now().UTC()
	eventID := uuid.New().String()
	ts := now.Format(time.RFC3339)

	item := map[string]types.AttributeValue{
		"EventID":    &types.AttributeValueMemberS{Value: eventID},
		"Timestamp":  &types.AttributeValueMemberS{Value: ts},
		"ActorID":    &types.AttributeValueMemberS{Value: actorID},
		"Action":     &types.AttributeValueMemberS{Value: string(action)},
		"ResourceID": &types.AttributeValueMemberS{Value: resourceID},
		"Outcome":    &types.AttributeValueMemberS{Value: string(outcome)},
	}

	if err := l.repo.PutAuditLog(ctx, item); err != nil {
		log.Printf(`{"level":"ERROR","message":"audit_log_write_failed","error":%q}`, err.Error())
	}

	entry := map[string]string{
		"level":       "INFO",
		"event_id":    eventID,
		"timestamp":   ts,
		"actor_id":    actorID,
		"action":      string(action),
		"resource_id": resourceID,
		"outcome":     string(outcome),
	}
	b, _ := json.Marshal(entry)
	log.Println(string(b))
}
