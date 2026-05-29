package repository_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/repository"
)

// ── Mock ──────────────────────────────────────────────────────────────────────

type mockDynamo struct{ mock.Mock }

func (m *mockDynamo) GetItem(ctx context.Context, p *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	args := m.Called(ctx, p)
	out, _ := args.Get(0).(*dynamodb.GetItemOutput)
	return out, args.Error(1)
}

func (m *mockDynamo) TransactWriteItems(ctx context.Context, p *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	args := m.Called(ctx, p)
	out, _ := args.Get(0).(*dynamodb.TransactWriteItemsOutput)
	return out, args.Error(1)
}

func (m *mockDynamo) PutItem(ctx context.Context, p *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	args := m.Called(ctx, p)
	out, _ := args.Get(0).(*dynamodb.PutItemOutput)
	return out, args.Error(1)
}

// ── GetPollResults ────────────────────────────────────────────────────────────

func TestGetPollResults_DBError(t *testing.T) {
	db := &mockDynamo{}
	db.On("GetItem", mock.Anything, mock.Anything).Return(nil, errors.New("dynamodb unavailable"))

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	item, err := repo.GetPollResults(context.Background(), "poll-001")

	assert.Nil(t, item)
	assert.ErrorContains(t, err, "dynamodb unavailable")
	db.AssertExpectations(t)
}

func TestGetPollResults_ItemNotFound(t *testing.T) {
	db := &mockDynamo{}
	db.On("GetItem", mock.Anything, mock.Anything).Return(&dynamodb.GetItemOutput{Item: nil}, nil)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	item, err := repo.GetPollResults(context.Background(), "poll-001")

	assert.NoError(t, err)
	assert.Equal(t, "poll-001", item.PollID)
	assert.Zero(t, item.OptionA)
	assert.Zero(t, item.OptionB)
	assert.Zero(t, item.OptionC)
	assert.Zero(t, item.OptionD)
}

// TestGetPollResults_WithCounts exercises all three branches of extractN:
//   - OptionA: valid number  (branch: success path)
//   - OptionB: missing key   (branch: attribute not present → 0)
//   - OptionC: wrong type    (branch: type assertion fails → 0)
//   - OptionD: valid number  (branch: success path, value 0)
func TestGetPollResults_WithCounts(t *testing.T) {
	db := &mockDynamo{}
	db.On("GetItem", mock.Anything, mock.Anything).Return(&dynamodb.GetItemOutput{
		Item: map[string]types.AttributeValue{
			"PollID":  &types.AttributeValueMemberS{Value: "poll-001"},
			"OptionA": &types.AttributeValueMemberN{Value: "42"},
			// OptionB intentionally absent  → extractN key-not-found branch
			"OptionC": &types.AttributeValueMemberS{Value: "not-a-number"}, // wrong type branch
			"OptionD": &types.AttributeValueMemberN{Value: "0"},
		},
	}, nil)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	item, err := repo.GetPollResults(context.Background(), "poll-001")

	assert.NoError(t, err)
	assert.EqualValues(t, 42, item.OptionA)
	assert.EqualValues(t, 0, item.OptionB)  // missing key
	assert.EqualValues(t, 0, item.OptionC)  // wrong type
	assert.EqualValues(t, 0, item.OptionD)
}

// ── CastVoteTransaction ───────────────────────────────────────────────────────

func TestCastVoteTransaction_Success(t *testing.T) {
	db := &mockDynamo{}
	db.On("TransactWriteItems", mock.Anything, mock.Anything).Return(&dynamodb.TransactWriteItemsOutput{}, nil)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.CastVoteTransaction(context.Background(), "hash123", "poll-001", "A", 9999999999)

	assert.NoError(t, err)
	db.AssertExpectations(t)
}

func TestCastVoteTransaction_DuplicateVote(t *testing.T) {
	code := "ConditionalCheckFailed"
	txErr := &types.TransactionCanceledException{
		CancellationReasons: []types.CancellationReason{{Code: &code}},
	}

	db := &mockDynamo{}
	db.On("TransactWriteItems", mock.Anything, mock.Anything).Return(nil, txErr)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.CastVoteTransaction(context.Background(), "hash123", "poll-001", "A", 9999999999)

	assert.ErrorIs(t, err, repository.ErrDuplicateVote)
}

func TestCastVoteTransaction_TransactionCancelledOtherReason(t *testing.T) {
	code := "TransactionConflict"
	txErr := &types.TransactionCanceledException{
		CancellationReasons: []types.CancellationReason{{Code: &code}},
	}

	db := &mockDynamo{}
	db.On("TransactWriteItems", mock.Anything, mock.Anything).Return(nil, txErr)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.CastVoteTransaction(context.Background(), "hash123", "poll-001", "A", 9999999999)

	assert.Error(t, err)
	assert.NotErrorIs(t, err, repository.ErrDuplicateVote)
}

func TestCastVoteTransaction_GenericError(t *testing.T) {
	db := &mockDynamo{}
	db.On("TransactWriteItems", mock.Anything, mock.Anything).Return(nil, errors.New("network error"))

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.CastVoteTransaction(context.Background(), "hash123", "poll-001", "A", 9999999999)

	assert.ErrorContains(t, err, "network error")
}

// ── PutAuditLog ───────────────────────────────────────────────────────────────

func TestPutAuditLog_Success(t *testing.T) {
	db := &mockDynamo{}
	db.On("PutItem", mock.Anything, mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.PutAuditLog(context.Background(), map[string]types.AttributeValue{
		"EventID": &types.AttributeValueMemberS{Value: aws.ToString(aws.String("evt-1"))},
	})

	assert.NoError(t, err)
	db.AssertExpectations(t)
}

func TestPutAuditLog_Error(t *testing.T) {
	db := &mockDynamo{}
	db.On("PutItem", mock.Anything, mock.Anything).Return(nil, errors.New("write denied"))

	repo := repository.New(db, "PollResults", "VoterLog", "AuditLog")
	err := repo.PutAuditLog(context.Background(), map[string]types.AttributeValue{})

	assert.ErrorContains(t, err, "write denied")
}
