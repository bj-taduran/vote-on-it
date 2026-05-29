package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/bj-taduran/vote-on-it/internal/model"
)

// ErrDuplicateVote is returned when VoterLog already contains the hashed voter fingerprint.
var ErrDuplicateVote = errors.New("duplicate vote")

// DynamoDBAPI is the subset of *dynamodb.Client used by Repo.
// Keeping this as an interface allows tests to substitute a mock without a live DynamoDB.
type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// Repo encapsulates all DynamoDB read/write operations.
// It contains no business logic and does not validate inputs.
type Repo struct {
	db               DynamoDBAPI
	pollResultsTable string
	voterLogTable    string
	auditLogTable    string
}

// New returns a Repo wired to the given DynamoDB client and table names.
func New(db DynamoDBAPI, pollResultsTable, voterLogTable, auditLogTable string) *Repo {
	return &Repo{
		db:               db,
		pollResultsTable: pollResultsTable,
		voterLogTable:    voterLogTable,
		auditLogTable:    auditLogTable,
	}
}

// GetPollResults fetches vote counters for the given pollID.
// Returns a zero-value item (all counts = 0) if no votes have been cast yet.
func (r *Repo) GetPollResults(ctx context.Context, pollID string) (*model.PollResultItem, error) {
	out, err := r.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.pollResultsTable),
		Key: map[string]types.AttributeValue{
			"PollID": &types.AttributeValueMemberS{Value: pollID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("GetItem PollResults: %w", err)
	}

	item := &model.PollResultItem{PollID: pollID}
	if out.Item != nil {
		item.OptionA = extractN(out.Item, "OptionA")
		item.OptionB = extractN(out.Item, "OptionB")
		item.OptionC = extractN(out.Item, "OptionC")
		item.OptionD = extractN(out.Item, "OptionD")
	}
	return item, nil
}

// CastVoteTransaction atomically:
//  1. Writes the voter hash to VoterLog with a condition that it must not already exist.
//  2. Increments the chosen option counter in PollResults using an atomic ADD.
//
// If the condition fails (voter already voted), ErrDuplicateVote is returned.
// All DynamoDB expressions use ExpressionAttributeValues — no raw input interpolation.
func (r *Repo) CastVoteTransaction(ctx context.Context, voterHash, pollID, option string, expiresAt int64) error {
	_, err := r.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				// Write the pseudonymised voter fingerprint. The ConditionExpression
				// ensures the transaction fails atomically if this exact (VoterHash, PollID)
				// pair already exists, preventing replay attacks without checking in advance.
				Put: &types.Put{
					TableName: aws.String(r.voterLogTable),
					Item: map[string]types.AttributeValue{
						"VoterHash": &types.AttributeValueMemberS{Value: voterHash},
						"PollID":    &types.AttributeValueMemberS{Value: pollID},
						"ExpiresAt": &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt, 10)},
					},
					// attribute_not_exists(VoterHash) on a composite-key table checks
					// whether the specific (VoterHash, PollID) item exists — equivalent
					// to "this vote has never been cast before."
					ConditionExpression: aws.String("attribute_not_exists(VoterHash)"),
				},
			},
			{
				// Atomically increment the chosen option. ADD creates the attribute if
				// absent (first vote on a poll) and adds 1 if it already exists.
				// ExpressionAttributeNames avoids reserved-word conflicts for option keys.
				Update: &types.Update{
					TableName: aws.String(r.pollResultsTable),
					Key: map[string]types.AttributeValue{
						"PollID": &types.AttributeValueMemberS{Value: pollID},
					},
					UpdateExpression: aws.String("ADD #opt :one"),
					ExpressionAttributeNames: map[string]string{
						"#opt": "Option" + option,
					},
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":one": &types.AttributeValueMemberN{Value: "1"},
					},
				},
			},
		},
	})
	if err != nil {
		var txErr *types.TransactionCanceledException
		if errors.As(err, &txErr) {
			for _, reason := range txErr.CancellationReasons {
				if aws.ToString(reason.Code) == "ConditionalCheckFailed" {
					return ErrDuplicateVote
				}
			}
		}
		return fmt.Errorf("TransactWriteItems: %w", err)
	}
	return nil
}

// PutAuditLog appends an immutable audit record. The Lambda IAM role has only
// PutItem on this table — UpdateItem and DeleteItem are explicitly denied.
func (r *Repo) PutAuditLog(ctx context.Context, item map[string]types.AttributeValue) error {
	_, err := r.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.auditLogTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("PutItem AuditLog: %w", err)
	}
	return nil
}

func extractN(item map[string]types.AttributeValue, key string) int64 {
	v, ok := item[key]
	if !ok {
		return 0
	}
	n, ok := v.(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	val, _ := strconv.ParseInt(n.Value, 10, 64)
	return val
}
