package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Single-table layout; see docs/DESIGN.md "Storage".
const (
	gsi1 = "GSI1"

	pkService = "SERVICE#"
	pkSlug    = "SLUG#"
	pkAudit   = "AUDIT#"
	skMeta    = "META"
	skCred    = "CRED#"
	gsiAll    = "SERVICES"

	pkOwner     = "OWNER#me"
	skPasskey   = "PASSKEY#"
	skSeen      = "SEEN#"
	pkChallenge = "CHALLENGE#"
	pkSession   = "SESSION#"
	pkRate      = "RATE#"
	pkResource  = "RESOURCE#"
	pkClient    = "CLIENT#"
	pkAuthz     = "AUTHZ#"
	pkCode      = "CODE#"
	pkRefresh   = "REFRESH#"
	gsiFamily   = "FAMILY#"
	skRecovery  = "RECOVERY#"
	pkUser      = "USER#"
	pkIdent     = "IDENT#"
	gsiUsers    = "USERS#"
	gsiUPK      = "UPK#"
	pkOrg       = "ORG#"
	skMember    = "MEMBER#"
	gsiOrgs     = "ORGS#"
	gsiUserOrgs = "USERORGS#"
	skInvite    = "INVITE#"
	gsiInvites  = "INVITES#"
)

// DynamoAPI is the slice of the DynamoDB client the store uses.
type DynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// Dynamo is the DynamoDB Store.
type Dynamo struct {
	db    DynamoAPI
	table string
}

// NewDynamo wraps a client and table name.
func NewDynamo(db DynamoAPI, table string) *Dynamo { return &Dynamo{db: db, table: table} }

type serviceItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string              `dynamodbav:"type"`
	ID                     string              `dynamodbav:"id"`
	Slug                   string              `dynamodbav:"slug"`
	Name                   string              `dynamodbav:"name"`
	Status                 string              `dynamodbav:"status"`
	CreatedAt              string              `dynamodbav:"created_at"`
	Resources              []string            `dynamodbav:"resources,omitempty"`
	Scopes                 []string            `dynamodbav:"scopes,omitempty"`
	Roles                  map[string][]string `dynamodbav:"roles,omitempty"`
	LoginURL               string              `dynamodbav:"login_url,omitempty"`
	RPID                   string              `dynamodbav:"rp_id,omitempty"`
	Origins                []string            `dynamodbav:"origins,omitempty"`
	DefaultRoles           []string            `dynamodbav:"default_roles,omitempty"`
	OpenSignup             bool                `dynamodbav:"open_signup,omitempty"`
}

type credItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ID                     string `dynamodbav:"id"`
	ServiceID              string `dynamodbav:"service_id"`
	Hash                   string `dynamodbav:"hash"`
	Last4                  string `dynamodbav:"last4"`
	CreatedAt              string `dynamodbav:"created_at"`
	RevokedAt              string `dynamodbav:"revoked_at,omitempty"`
}

func (d *Dynamo) CreateService(ctx context.Context, s Service) error {
	item, err := attributevalue.MarshalMap(serviceItem{
		PK: pkService + s.ID, SK: skMeta, GSI1PK: gsiAll, GSI1SK: s.Slug,
		Type: "service", ID: s.ID, Slug: s.Slug, Name: s.Name, Status: s.Status,
		CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	lock, err := attributevalue.MarshalMap(map[string]string{"PK": pkSlug + s.Slug, "SK": skMeta, "service_id": s.ID})
	if err != nil {
		return err
	}
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: &d.table, Item: lock, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetService(ctx context.Context, id string) (Service, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkService+id, skMeta)})
	if err != nil {
		return Service{}, err
	}
	if out.Item == nil {
		return Service{}, ErrNotFound
	}
	var it serviceItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return Service{}, err
	}
	return it.toService()
}

func (d *Dynamo) ListServices(ctx context.Context) ([]Service, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiAll}},
	})
	if err != nil {
		return nil, err
	}
	var items []serviceItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	svcs := make([]Service, 0, len(items))
	for _, it := range items {
		s, err := it.toService()
		if err != nil {
			return nil, err
		}
		svcs = append(svcs, s)
	}
	return svcs, nil
}

func (d *Dynamo) PutCredential(ctx context.Context, c Credential) error {
	item, err := attributevalue.MarshalMap(credItem{
		PK: pkService + c.ServiceID, SK: skCred + c.ID, GSI1PK: skCred + c.ID, GSI1SK: pkService + c.ServiceID,
		Type: "credential", ID: c.ID, ServiceID: c.ServiceID, Hash: c.Hash, Last4: c.Last4,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetCredential(ctx context.Context, credID string) (Credential, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: skCred + credID}},
		Limit:                     aws.Int32(1),
	})
	if err != nil {
		return Credential{}, err
	}
	if len(out.Items) == 0 {
		return Credential{}, ErrNotFound
	}
	var it credItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &it); err != nil {
		return Credential{}, err
	}
	return it.toCredential()
}

func (d *Dynamo) ListCredentials(ctx context.Context, serviceID string) ([]Credential, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkService + serviceID},
			":s": &types.AttributeValueMemberS{Value: skCred},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []credItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	creds := make([]Credential, 0, len(items))
	for _, it := range items {
		c, err := it.toCredential()
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (d *Dynamo) RevokeCredential(ctx context.Context, serviceID, credID string, at time.Time) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           &d.table,
		Key:                 dynKey(pkService+serviceID, skCred+credID),
		UpdateExpression:    aws.String("SET revoked_at = if_not_exists(revoked_at, :t)"),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": &types.AttributeValueMemberS{Value: at.UTC().Format(time.RFC3339Nano)},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) AppendAudit(ctx context.Context, e AuditEvent) error {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	ts := e.At.UTC().Format(time.RFC3339Nano)
	item, err := attributevalue.MarshalMap(map[string]string{
		"PK": pkAudit + e.At.UTC().Format("2006-01"), "SK": ts + "#" + hex.EncodeToString(r[:]),
		"type": "audit", "at": ts, "kind": e.Kind, "actor": e.Actor, "service_id": e.ServiceID,
		"detail": e.Detail, "ip": e.IP,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func dynKey(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: pk},
		"SK": &types.AttributeValueMemberS{Value: sk},
	}
}

func (it serviceItem) toService() (Service, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return Service{}, fmt.Errorf("store: bad created_at on %s: %w", it.PK, err)
	}
	return Service{ID: it.ID, Slug: it.Slug, Name: it.Name, Status: it.Status, CreatedAt: t, Resources: it.Resources, Scopes: it.Scopes, Roles: it.Roles,
		LoginURL: it.LoginURL, RPID: it.RPID, Origins: it.Origins, DefaultRoles: it.DefaultRoles, OpenSignup: it.OpenSignup}, nil
}

func (it credItem) toCredential() (Credential, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return Credential{}, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
	}
	c := Credential{ID: it.ID, ServiceID: it.ServiceID, Hash: it.Hash, Last4: it.Last4, CreatedAt: t}
	if it.RevokedAt != "" {
		r, err := time.Parse(time.RFC3339Nano, it.RevokedAt)
		if err != nil {
			return Credential{}, fmt.Errorf("store: bad revoked_at on %s/%s: %w", it.PK, it.SK, err)
		}
		c.RevokedAt = &r
	}
	return c, nil
}

type passkeyItem struct {
	PK, SK    string
	Type      string `dynamodbav:"type"`
	ID        string `dynamodbav:"id"`
	Name      string `dynamodbav:"name"`
	CreatedAt string `dynamodbav:"created_at"`
	Data      []byte `dynamodbav:"data"`
}

type expiringItem struct {
	PK, SK     string
	Type       string `dynamodbav:"type"`
	CreatedAt  string `dynamodbav:"created_at,omitempty"`
	ExpiresAt  string `dynamodbav:"expires_at"`
	IP         string `dynamodbav:"ip,omitempty"`
	Method     string `dynamodbav:"method,omitempty"`
	VerifiedAt string `dynamodbav:"verified_at,omitempty"`
	Data       []byte `dynamodbav:"data,omitempty"`
	// TTL is the table's TTL attribute: DynamoDB deletes the row within ~48h
	// of this epoch second. Expiry is still enforced in code.
	TTL int64 `dynamodbav:"ttl"`
}

func (d *Dynamo) PutPasskey(ctx context.Context, p Passkey) error {
	item, err := attributevalue.MarshalMap(passkeyItem{
		PK: pkOwner, SK: skPasskey + p.ID, Type: "passkey", ID: p.ID, Name: p.Name,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339Nano), Data: p.Data,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) UpdatePasskey(ctx context.Context, p Passkey) error {
	if len(p.Data) == 0 {
		return errors.New("store: passkey data required")
	}
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkOwner, skPasskey+p.ID),
		UpdateExpression:         aws.String("SET #d = :d, #n = :n"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#d": "data", "#n": "name"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":d": &types.AttributeValueMemberB{Value: p.Data},
			":n": &types.AttributeValueMemberS{Value: p.Name},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) ListPasskeys(ctx context.Context) ([]Passkey, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkOwner},
			":s": &types.AttributeValueMemberS{Value: skPasskey},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []passkeyItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	keys := make([]Passkey, 0, len(items))
	for _, it := range items {
		t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
		}
		keys = append(keys, Passkey{ID: it.ID, Name: it.Name, CreatedAt: t, Data: it.Data})
	}
	return keys, nil
}

func (d *Dynamo) PutChallenge(ctx context.Context, id string, data []byte, expires time.Time) error {
	item, err := attributevalue.MarshalMap(expiringItem{
		PK: pkChallenge + id, SK: skMeta, Type: "challenge", Data: data,
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano), TTL: expires.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) ConsumeChallenge(ctx context.Context, id string, now time.Time) ([]byte, error) {
	out, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &d.table, Key: dynKey(pkChallenge+id, skMeta), ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, err
	}
	if out.Attributes == nil {
		return nil, ErrNotFound
	}
	var it expiringItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return nil, ErrNotFound
	}
	return it.Data, nil
}

func (d *Dynamo) PutSession(ctx context.Context, s Session) error {
	item, err := attributevalue.MarshalMap(expiringItem{
		PK: pkSession + s.Hash, SK: skMeta, Type: "session", IP: s.IP, Method: s.Method,
		VerifiedAt: fmtTime(s.VerifiedAt),
		CreatedAt:  s.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:  s.ExpiresAt.UTC().Format(time.RFC3339Nano), TTL: s.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) GetSession(ctx context.Context, hash string, now time.Time) (Session, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkSession+hash, skMeta)})
	if err != nil {
		return Session{}, err
	}
	if out.Item == nil {
		return Session{}, ErrNotFound
	}
	var it expiringItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return Session{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return Session{}, ErrNotFound
	}
	created, _ := time.Parse(time.RFC3339Nano, it.CreatedAt)
	verified, _ := time.Parse(time.RFC3339Nano, it.VerifiedAt)
	return Session{Hash: hash, CreatedAt: created, ExpiresAt: exp, IP: it.IP, Method: it.Method, VerifiedAt: verified}, nil
}

func (d *Dynamo) DeleteSession(ctx context.Context, hash string) error {
	_, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkSession+hash, skMeta)})
	return err
}

type rateItem struct {
	PK, SK string
	Type   string `dynamodbav:"type"`
	Count  int    `dynamodbav:"count"`
	Until  int64  `dynamodbav:"until"` // epoch seconds the window ends
	TTL    int64  `dynamodbav:"ttl"`
}

func (d *Dynamo) FailureCount(ctx context.Context, key string, now time.Time) (int, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkRate+key, skMeta)})
	if err != nil {
		return 0, err
	}
	if out.Item == nil {
		return 0, nil
	}
	var it rateItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return 0, err
	}
	if now.Unix() >= it.Until {
		return 0, nil
	}
	return it.Count, nil
}

// RecordFailure increments the counter inside a live window, or starts a new
// window when none is live. Two steps, both conditional, so concurrent
// failures never lose a count.
func (d *Dynamo) RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration) (int, error) {
	out, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkRate+key, skMeta),
		UpdateExpression:         aws.String("ADD #c :one"),
		ConditionExpression:      aws.String("attribute_exists(PK) AND #u > :now"),
		ExpressionAttributeNames: map[string]string{"#c": "count", "#u": "until"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":now": &types.AttributeValueMemberN{Value: fmt.Sprint(now.Unix())},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		// No live window: start one at 1.
		until := now.Add(window).Unix()
		item, err := attributevalue.MarshalMap(rateItem{PK: pkRate + key, SK: skMeta, Type: "rate", Count: 1, Until: until, TTL: until + 60})
		if err != nil {
			return 0, err
		}
		if _, err := d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	var it rateItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return 0, err
	}
	return it.Count, nil
}

// ── resources ──────────────────────────────────────────────────────────────

func (d *Dynamo) AddServiceResource(ctx context.Context, serviceID, resource string) error {
	lock, err := attributevalue.MarshalMap(map[string]string{"PK": pkResource + resource, "SK": skMeta, "type": "resource", "service_id": serviceID})
	if err != nil {
		return err
	}
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: &d.table, Item: lock, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Update: &types.Update{
				TableName:           &d.table,
				Key:                 dynKey(pkService+serviceID, skMeta),
				UpdateExpression:    aws.String("SET resources = list_append(if_not_exists(resources, :empty), :r)"),
				ConditionExpression: aws.String("attribute_exists(PK)"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":empty": &types.AttributeValueMemberL{Value: []types.AttributeValue{}},
					":r":     &types.AttributeValueMemberL{Value: []types.AttributeValue{&types.AttributeValueMemberS{Value: resource}}},
				},
			}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		// First reason is the lock (resource taken); second is the service (missing).
		if len(canceled.CancellationReasons) == 2 && aws.ToString(canceled.CancellationReasons[1].Code) == "ConditionalCheckFailed" {
			return ErrNotFound
		}
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetServiceByResource(ctx context.Context, resource string) (Service, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkResource+resource, skMeta)})
	if err != nil {
		return Service{}, err
	}
	if out.Item == nil {
		return Service{}, ErrNotFound
	}
	var lock struct {
		ServiceID string `dynamodbav:"service_id"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &lock); err != nil {
		return Service{}, err
	}
	return d.GetService(ctx, lock.ServiceID)
}

// ── oauth ──────────────────────────────────────────────────────────────────

type clientItem struct {
	PK, SK       string
	Type         string   `dynamodbav:"type"`
	ID           string   `dynamodbav:"id"`
	Name         string   `dynamodbav:"name"`
	SecretHash   string   `dynamodbav:"secret_hash,omitempty"`
	AuthMethod   string   `dynamodbav:"auth_method"`
	RedirectURIs []string `dynamodbav:"redirect_uris"`
	CreatedAt    string   `dynamodbav:"created_at"`
}

func (d *Dynamo) CreateOAuthClient(ctx context.Context, c OAuthClient) error {
	item, err := attributevalue.MarshalMap(clientItem{
		PK: pkClient + c.ID, SK: skMeta, Type: "oauth_client", ID: c.ID, Name: c.Name, SecretHash: c.SecretHash,
		AuthMethod: c.AuthMethod, RedirectURIs: c.RedirectURIs, CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetOAuthClient(ctx context.Context, id string) (OAuthClient, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkClient+id, skMeta)})
	if err != nil {
		return OAuthClient{}, err
	}
	if out.Item == nil {
		return OAuthClient{}, ErrNotFound
	}
	var it clientItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return OAuthClient{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return OAuthClient{}, fmt.Errorf("store: bad created_at on %s: %w", it.PK, err)
	}
	return OAuthClient{ID: it.ID, Name: it.Name, SecretHash: it.SecretHash, AuthMethod: it.AuthMethod, RedirectURIs: it.RedirectURIs, CreatedAt: t}, nil
}

type authzItem struct {
	PK, SK      string
	Type        string `dynamodbav:"type"`
	ID          string `dynamodbav:"id"`
	ClientID    string `dynamodbav:"client_id"`
	RedirectURI string `dynamodbav:"redirect_uri"`
	State       string `dynamodbav:"state,omitempty"`
	Scope       string `dynamodbav:"scope,omitempty"`
	Challenge   string `dynamodbav:"challenge"`
	Resource    string `dynamodbav:"resource"`
	ServiceID   string `dynamodbav:"service_id"`
	Org         string `dynamodbav:"org,omitempty"`
	ExpiresAt   string `dynamodbav:"expires_at"`
	TTL         int64  `dynamodbav:"ttl"`
}

func (d *Dynamo) PutAuthzRequest(ctx context.Context, a AuthzRequest) error {
	item, err := attributevalue.MarshalMap(authzItem{
		PK: pkAuthz + a.ID, SK: skMeta, Type: "authz", ID: a.ID, ClientID: a.ClientID, RedirectURI: a.RedirectURI, State: a.State,
		Scope: a.Scope, Challenge: a.Challenge, Resource: a.Resource, ServiceID: a.ServiceID, Org: a.Org,
		ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339Nano), TTL: a.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) GetAuthzRequest(ctx context.Context, id string, now time.Time) (AuthzRequest, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkAuthz+id, skMeta)})
	if err != nil {
		return AuthzRequest{}, err
	}
	if out.Item == nil {
		return AuthzRequest{}, ErrNotFound
	}
	var it authzItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return AuthzRequest{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return AuthzRequest{}, ErrNotFound
	}
	return AuthzRequest{ID: it.ID, ClientID: it.ClientID, RedirectURI: it.RedirectURI, State: it.State, Scope: it.Scope,
		Challenge: it.Challenge, Resource: it.Resource, ServiceID: it.ServiceID, Org: it.Org, ExpiresAt: exp}, nil
}

func (d *Dynamo) DeleteAuthzRequest(ctx context.Context, id string) error {
	_, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkAuthz+id, skMeta)})
	return err
}

type codeItem struct {
	PK, SK      string
	Type        string `dynamodbav:"type"`
	ClientID    string `dynamodbav:"client_id"`
	RedirectURI string `dynamodbav:"redirect_uri"`
	Challenge   string `dynamodbav:"challenge"`
	Scope       string `dynamodbav:"scope,omitempty"`
	Subject     string `dynamodbav:"subject"`
	ServiceID   string `dynamodbav:"service_id"`
	Org         string `dynamodbav:"org,omitempty"`
	OrgRole     string `dynamodbav:"org_role,omitempty"`
	ExpiresAt   string `dynamodbav:"expires_at"`
	TTL         int64  `dynamodbav:"ttl"`
}

func (d *Dynamo) CreateCode(ctx context.Context, hash string, c Code) error {
	item, err := attributevalue.MarshalMap(codeItem{
		PK: pkCode + hash, SK: skMeta, Type: "code", ClientID: c.ClientID, RedirectURI: c.RedirectURI, Challenge: c.Challenge,
		Scope: c.Scope, Subject: c.Subject, ServiceID: c.ServiceID, Org: c.Org, OrgRole: c.OrgRole,
		ExpiresAt: c.ExpiresAt.UTC().Format(time.RFC3339Nano), TTL: c.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) ConsumeCode(ctx context.Context, hash string, now time.Time) (Code, error) {
	out, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkCode+hash, skMeta), ReturnValues: types.ReturnValueAllOld})
	if err != nil {
		return Code{}, err
	}
	if out.Attributes == nil {
		return Code{}, ErrNotFound
	}
	var it codeItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return Code{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return Code{}, ErrNotFound
	}
	return Code{ClientID: it.ClientID, RedirectURI: it.RedirectURI, Challenge: it.Challenge, Scope: it.Scope, Subject: it.Subject, ServiceID: it.ServiceID,
		Org: it.Org, OrgRole: it.OrgRole, ExpiresAt: exp}, nil
}

type refreshItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	Family                 string `dynamodbav:"family"`
	ClientID               string `dynamodbav:"client_id"`
	ServiceID              string `dynamodbav:"service_id"`
	Subject                string `dynamodbav:"subject"`
	Scope                  string `dynamodbav:"scope,omitempty"`
	Org                    string `dynamodbav:"org,omitempty"`
	OrgRole                string `dynamodbav:"org_role,omitempty"`
	IssuedAt               string `dynamodbav:"issued_at,omitempty"`
	ExpiresAt              string `dynamodbav:"expires_at"`
	Used                   bool   `dynamodbav:"used"`
	TTL                    int64  `dynamodbav:"ttl"`
}

func (it refreshItem) toToken() (RefreshToken, error) {
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("store: bad expires_at on %s: %w", it.PK, err)
	}
	issued, _ := time.Parse(time.RFC3339Nano, it.IssuedAt)
	return RefreshToken{Hash: strings.TrimPrefix(it.PK, pkRefresh), Family: it.Family, ClientID: it.ClientID, ServiceID: it.ServiceID,
		Subject: it.Subject, Scope: it.Scope, Org: it.Org, OrgRole: it.OrgRole, IssuedAt: issued, ExpiresAt: exp, Used: it.Used}, nil
}

func (d *Dynamo) CreateRefresh(ctx context.Context, t RefreshToken) error {
	item, err := attributevalue.MarshalMap(refreshItem{
		PK: pkRefresh + t.Hash, SK: skMeta, GSI1PK: gsiFamily + t.Family, GSI1SK: pkRefresh + t.Hash, Type: "refresh",
		Family: t.Family, ClientID: t.ClientID, ServiceID: t.ServiceID, Subject: t.Subject, Scope: t.Scope, Org: t.Org, OrgRole: t.OrgRole,
		IssuedAt:  t.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339Nano), Used: false, TTL: t.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) ConsumeRefresh(ctx context.Context, hash string, now time.Time) (RefreshToken, bool, error) {
	out, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       dynKey(pkRefresh+hash, skMeta),
		UpdateExpression:          aws.String("SET used = :t"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND used = :f"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}, ":f": &types.AttributeValueMemberBOOL{Value: false}},
		ReturnValues:              types.ReturnValueAllNew,
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		// Missing, or already used: look to tell which.
		got, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkRefresh+hash, skMeta)})
		if err != nil {
			return RefreshToken{}, false, err
		}
		if got.Item == nil {
			return RefreshToken{}, false, ErrNotFound
		}
		var it refreshItem
		if err := attributevalue.UnmarshalMap(got.Item, &it); err != nil {
			return RefreshToken{}, false, err
		}
		t, err := it.toToken()
		if err != nil || !now.Before(t.ExpiresAt) {
			return RefreshToken{}, false, ErrNotFound
		}
		return t, true, nil
	}
	if err != nil {
		return RefreshToken{}, false, err
	}
	var it refreshItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return RefreshToken{}, false, err
	}
	t, err := it.toToken()
	if err != nil {
		return RefreshToken{}, false, err
	}
	if !now.Before(t.ExpiresAt) {
		return RefreshToken{}, false, ErrNotFound
	}
	return t, false, nil
}

func (d *Dynamo) RevokeRefreshFamily(ctx context.Context, family string) error {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiFamily + family}},
		ProjectionExpression:      aws.String("PK, SK"),
	})
	if err != nil {
		return err
	}
	for _, item := range out.Items {
		pk, _ := item["PK"].(*types.AttributeValueMemberS)
		if pk == nil {
			continue
		}
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pk.Value, skMeta)}); err != nil {
			return err
		}
	}
	return nil
}

// ── recovery codes ─────────────────────────────────────────────────────────

type recoveryItem struct {
	PK, SK    string
	Type      string `dynamodbav:"type"`
	CreatedAt string `dynamodbav:"created_at"`
	UsedAt    string `dynamodbav:"used_at,omitempty"`
}

func (d *Dynamo) ReplaceRecoveryCodes(ctx context.Context, hashes []string, created time.Time) error {
	old, err := d.ListRecoveryCodes(ctx)
	if err != nil {
		return err
	}
	for _, c := range old {
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkOwner, skRecovery+c.Hash)}); err != nil {
			return err
		}
	}
	for _, h := range hashes {
		item, err := attributevalue.MarshalMap(recoveryItem{PK: pkOwner, SK: skRecovery + h, Type: "recovery", CreatedAt: created.UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		if _, err := d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dynamo) ListRecoveryCodes(ctx context.Context) ([]RecoveryCode, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkOwner},
			":s": &types.AttributeValueMemberS{Value: skRecovery},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []recoveryItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	codes := make([]RecoveryCode, 0, len(items))
	for _, it := range items {
		t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
		}
		c := RecoveryCode{Hash: strings.TrimPrefix(it.SK, skRecovery), CreatedAt: t}
		if it.UsedAt != "" {
			u, err := time.Parse(time.RFC3339Nano, it.UsedAt)
			if err != nil {
				return nil, fmt.Errorf("store: bad used_at on %s/%s: %w", it.PK, it.SK, err)
			}
			c.UsedAt = &u
		}
		codes = append(codes, c)
	}
	return codes, nil
}

func (d *Dynamo) ConsumeRecoveryCode(ctx context.Context, hash string, now time.Time) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       dynKey(pkOwner, skRecovery+hash),
		UpdateExpression:          aws.String("SET used_at = :t"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND attribute_not_exists(used_at)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberS{Value: now.UTC().Format(time.RFC3339Nano)}},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

// ── audit reader ───────────────────────────────────────────────────────────

type auditItem struct {
	PK, SK    string
	At        string `dynamodbav:"at"`
	Kind      string `dynamodbav:"kind"`
	Actor     string `dynamodbav:"actor"`
	ServiceID string `dynamodbav:"service_id"`
	Detail    string `dynamodbav:"detail"`
	IP        string `dynamodbav:"ip"`
}

func (d *Dynamo) ListAudit(ctx context.Context, month string, limit int, cursor string) ([]AuditEvent, string, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &d.table,
		KeyConditionExpression:    aws.String("PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: pkAudit + month}},
		ScanIndexForward:          aws.Bool(false),
		// One extra row tells us whether a next page exists; DynamoDB's own
		// LastEvaluatedKey is set even when the page exactly drained the data.
		Limit: aws.Int32(int32(limit + 1)), //nolint:gosec // limit is clamped by the caller
	}
	if cursor != "" {
		in.ExclusiveStartKey = dynKey(pkAudit+month, cursor)
	}
	out, err := d.db.Query(ctx, in)
	if err != nil {
		return nil, "", err
	}
	var items []auditItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].SK
	}
	events := make([]AuditEvent, 0, len(items))
	for _, it := range items {
		at, _ := time.Parse(time.RFC3339Nano, it.At)
		events = append(events, AuditEvent{At: at, Kind: it.Kind, Actor: it.Actor, ServiceID: it.ServiceID, Detail: it.Detail, IP: it.IP})
	}
	return events, next, nil
}

// ── owner not-before ───────────────────────────────────────────────────────

func (d *Dynamo) GetOwnerNotBefore(ctx context.Context) (time.Time, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkOwner, skMeta)})
	if err != nil {
		return time.Time{}, err
	}
	if out.Item == nil {
		return time.Time{}, nil
	}
	var it struct {
		NotBefore string `dynamodbav:"sessions_not_before"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil || it.NotBefore == "" {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, it.NotBefore)
}

func (d *Dynamo) SetOwnerNotBefore(ctx context.Context, t time.Time) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       dynKey(pkOwner, skMeta),
		UpdateExpression:          aws.String("SET sessions_not_before = :t, #t = :type"),
		ExpressionAttributeNames:  map[string]string{"#t": "type"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberS{Value: t.UTC().Format(time.RFC3339Nano)}, ":type": &types.AttributeValueMemberS{Value: "owner"}},
	})
	return err
}

func (d *Dynamo) TouchSessionVerified(ctx context.Context, hash string, at time.Time) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       dynKey(pkSession+hash, skMeta),
		UpdateExpression:          aws.String("SET verified_at = :t"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberS{Value: at.UTC().Format(time.RFC3339Nano)}},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

// fmtTime renders a time for storage; zero becomes "" (omitted).
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (d *Dynamo) UpdateServicePermissions(ctx context.Context, serviceID string, scopes []string, roles map[string][]string) error {
	scopesAV, err := attributevalue.MarshalList(scopes)
	if err != nil {
		return err
	}
	rolesAV, err := attributevalue.MarshalMap(roles)
	if err != nil {
		return err
	}
	if scopes == nil {
		scopesAV = []types.AttributeValue{}
	}
	_, err = d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkService+serviceID, skMeta),
		UpdateExpression:         aws.String("SET scopes = :s, #r = :r"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#r": "roles"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":s": &types.AttributeValueMemberL{Value: scopesAV},
			":r": &types.AttributeValueMemberM{Value: rolesAV},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) UpdateServiceLogin(ctx context.Context, serviceID, loginURL, rpID string, origins, defaultRoles []string, openSignup bool) error {
	strList := func(xs []string) types.AttributeValue {
		out := make([]types.AttributeValue, 0, len(xs))
		for _, x := range xs {
			out = append(out, &types.AttributeValueMemberS{Value: x})
		}
		return &types.AttributeValueMemberL{Value: out}
	}
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           &d.table,
		Key:                 dynKey(pkService+serviceID, skMeta),
		UpdateExpression:    aws.String("SET login_url = :l, rp_id = :r, origins = :o, default_roles = :d, open_signup = :s"),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":l": &types.AttributeValueMemberS{Value: loginURL},
			":r": &types.AttributeValueMemberS{Value: rpID},
			":o": strList(origins),
			":d": strList(defaultRoles),
			":s": &types.AttributeValueMemberBOOL{Value: openSignup},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

// ── end users ──────────────────────────────────────────────────────────────

type userItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string   `dynamodbav:"type"`
	ID                     string   `dynamodbav:"id"`
	ServiceID              string   `dynamodbav:"service_id"`
	Method                 string   `dynamodbav:"method"`
	Identity               string   `dynamodbav:"identity"`
	Email                  string   `dynamodbav:"email,omitempty"`
	Name                   string   `dynamodbav:"name,omitempty"`
	Roles                  []string `dynamodbav:"roles,omitempty"`
	Status                 string   `dynamodbav:"status"`
	CreatedAt              string   `dynamodbav:"created_at"`
	NotBefore              string   `dynamodbav:"sessions_not_before,omitempty"`
	EmailVerified          bool     `dynamodbav:"email_verified,omitempty"`
	LastLoginAt            string   `dynamodbav:"last_login_at,omitempty"`
}

func (it userItem) toUser() (User, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("store: bad created_at on %s: %w", it.PK, err)
	}
	nb, _ := time.Parse(time.RFC3339Nano, it.NotBefore)
	ll, _ := time.Parse(time.RFC3339Nano, it.LastLoginAt)
	return User{ID: it.ID, ServiceID: it.ServiceID, Method: it.Method, Identity: it.Identity, Email: it.Email, Name: it.Name,
		Roles: it.Roles, Status: it.Status, CreatedAt: t, NotBefore: nb, EmailVerified: it.EmailVerified, LastLoginAt: ll}, nil
}

func (d *Dynamo) CreateUser(ctx context.Context, u User) error {
	item, err := attributevalue.MarshalMap(userItem{
		PK: pkUser + u.ServiceID + "#" + u.ID, SK: skMeta, GSI1PK: gsiUsers + u.ServiceID, GSI1SK: u.CreatedAt.UTC().Format(time.RFC3339Nano) + "#" + u.ID,
		Type: "user", ID: u.ID, ServiceID: u.ServiceID, Method: u.Method, Identity: u.Identity, Email: u.Email, Name: u.Name,
		Roles: u.Roles, Status: u.Status, CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339Nano), NotBefore: fmtTime(u.NotBefore),
		EmailVerified: u.EmailVerified, LastLoginAt: fmtTime(u.LastLoginAt),
	})
	if err != nil {
		return err
	}
	lock, err := attributevalue.MarshalMap(map[string]string{"PK": pkIdent + u.ServiceID + "#" + u.Identity, "SK": skMeta, "type": "identity", "user_id": u.ID})
	if err != nil {
		return err
	}
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: &d.table, Item: lock, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetUser(ctx context.Context, serviceID, id string) (User, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkUser+serviceID+"#"+id, skMeta)})
	if err != nil {
		return User{}, err
	}
	if out.Item == nil {
		return User{}, ErrNotFound
	}
	var it userItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return User{}, err
	}
	return it.toUser()
}

func (d *Dynamo) GetUserByIdentity(ctx context.Context, serviceID, identity string) (User, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkIdent+serviceID+"#"+identity, skMeta)})
	if err != nil {
		return User{}, err
	}
	if out.Item == nil {
		return User{}, ErrNotFound
	}
	var lock struct {
		UserID string `dynamodbav:"user_id"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &lock); err != nil {
		return User{}, err
	}
	return d.GetUser(ctx, serviceID, lock.UserID)
}

func (d *Dynamo) ListUsers(ctx context.Context, serviceID string, limit int, cursor string) ([]User, string, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiUsers + serviceID}},
		Limit:                     aws.Int32(int32(limit + 1)), //nolint:gosec // limit is clamped by the caller
	}
	if cursor != "" {
		// cursor = "<GSI1SK>|<PK>" (the index key plus the table key).
		gsk, pk, ok := strings.Cut(cursor, "|")
		if !ok {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"GSI1PK": &types.AttributeValueMemberS{Value: gsiUsers + serviceID}, "GSI1SK": &types.AttributeValueMemberS{Value: gsk},
			"PK": &types.AttributeValueMemberS{Value: pk}, "SK": &types.AttributeValueMemberS{Value: skMeta},
		}
	}
	out, err := d.db.Query(ctx, in)
	if err != nil {
		return nil, "", err
	}
	var items []userItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].GSI1SK + "|" + items[limit-1].PK
	}
	users := make([]User, 0, len(items))
	for _, it := range items {
		u, err := it.toUser()
		if err != nil {
			return nil, "", err
		}
		users = append(users, u)
	}
	return users, next, nil
}

func (d *Dynamo) UpdateUser(ctx context.Context, u User) error {
	roles := make([]types.AttributeValue, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, &types.AttributeValueMemberS{Value: r})
	}
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkUser+u.ServiceID+"#"+u.ID, skMeta),
		UpdateExpression:         aws.String("SET email = :e, #n = :n, #r = :r, #s = :s, sessions_not_before = :nb, email_verified = :v, last_login_at = :ll"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#n": "name", "#r": "roles", "#s": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":e":  &types.AttributeValueMemberS{Value: u.Email},
			":n":  &types.AttributeValueMemberS{Value: u.Name},
			":r":  &types.AttributeValueMemberL{Value: roles},
			":s":  &types.AttributeValueMemberS{Value: u.Status},
			":nb": &types.AttributeValueMemberS{Value: fmtTime(u.NotBefore)},
			":v":  &types.AttributeValueMemberBOOL{Value: u.EmailVerified},
			":ll": &types.AttributeValueMemberS{Value: fmtTime(u.LastLoginAt)},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) RebindUserIdentity(ctx context.Context, serviceID, userID, oldIdentity, newIdentity string) error {
	lock, err := attributevalue.MarshalMap(map[string]string{"PK": pkIdent + serviceID + "#" + newIdentity, "SK": skMeta, "type": "identity", "user_id": userID})
	if err != nil {
		return err
	}
	// Old lock (must belong to this user), new lock (must be free) and the user
	// row move together, so a failure leaves the account exactly as it was.
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: &d.table, Key: dynKey(pkIdent+serviceID+"#"+oldIdentity, skMeta),
				ConditionExpression:       aws.String("attribute_exists(PK) AND user_id = :u"),
				ExpressionAttributeValues: map[string]types.AttributeValue{":u": &types.AttributeValueMemberS{Value: userID}}}},
			{Put: &types.Put{TableName: &d.table, Item: lock, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Update: &types.Update{TableName: &d.table, Key: dynKey(pkUser+serviceID+"#"+userID, skMeta),
				UpdateExpression:          aws.String("SET #i = :i"),
				ConditionExpression:       aws.String("attribute_exists(PK) AND #i = :o"),
				ExpressionAttributeNames:  map[string]string{"#i": "identity"},
				ExpressionAttributeValues: map[string]types.AttributeValue{":i": &types.AttributeValueMemberS{Value: newIdentity}, ":o": &types.AttributeValueMemberS{Value: oldIdentity}}}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		for i, r := range canceled.CancellationReasons {
			if r.Code != nil && *r.Code == "ConditionalCheckFailed" && i == 1 {
				return ErrConflict
			}
		}
		return ErrNotFound
	}
	return err
}

// TouchSeenIP keeps one row per (user, ip) under the user's partition,
// expired by DynamoDB TTL, so a sign-in from an address not seen in the
// window can raise a new-login alert.
func (d *Dynamo) TouchSeenIP(ctx context.Context, serviceID, userID, ip string, now time.Time, ttl time.Duration) (bool, error) {
	exp := now.Add(ttl)
	out, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkUser+serviceID+"#"+userID, skSeen+ip),
		UpdateExpression:         aws.String("SET #t = :t, expires_at = :e, #ttl = :ttl, last_seen_at = :now"),
		ExpressionAttributeNames: map[string]string{"#t": "type", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t":   &types.AttributeValueMemberS{Value: "seen_ip"},
			":e":   &types.AttributeValueMemberS{Value: exp.UTC().Format(time.RFC3339Nano)},
			":ttl": &types.AttributeValueMemberN{Value: strconv.FormatInt(exp.Unix()+60, 10)},
			":now": &types.AttributeValueMemberS{Value: now.UTC().Format(time.RFC3339Nano)},
		},
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return false, err
	}
	if old, ok := out.Attributes["expires_at"].(*types.AttributeValueMemberS); ok {
		if t, err := time.Parse(time.RFC3339Nano, old.Value); err == nil && now.Before(t) {
			return true, nil
		}
	}
	return false, nil
}

type userPasskeyItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ID                     string `dynamodbav:"id"`
	ServiceID              string `dynamodbav:"service_id"`
	UserID                 string `dynamodbav:"user_id"`
	Name                   string `dynamodbav:"name"`
	CreatedAt              string `dynamodbav:"created_at"`
	Data                   []byte `dynamodbav:"data"`
}

func (it userPasskeyItem) toPasskey() (UserPasskey, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return UserPasskey{}, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
	}
	return UserPasskey{ServiceID: it.ServiceID, UserID: it.UserID, ID: it.ID, Name: it.Name, CreatedAt: t, Data: it.Data}, nil
}

func (d *Dynamo) PutUserPasskey(ctx context.Context, p UserPasskey) error {
	item, err := attributevalue.MarshalMap(userPasskeyItem{
		PK: pkUser + p.ServiceID + "#" + p.UserID, SK: skPasskey + p.ID, GSI1PK: gsiUPK + p.ServiceID + "#" + p.ID, GSI1SK: p.UserID,
		Type: "user_passkey", ID: p.ID, ServiceID: p.ServiceID, UserID: p.UserID, Name: p.Name,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339Nano), Data: p.Data,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) UpdateUserPasskey(ctx context.Context, p UserPasskey) error {
	if len(p.Data) == 0 {
		return errors.New("store: passkey data required")
	}
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &d.table,
		Key:                       dynKey(pkUser+p.ServiceID+"#"+p.UserID, skPasskey+p.ID),
		UpdateExpression:          aws.String("SET #d = :d"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  map[string]string{"#d": "data"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":d": &types.AttributeValueMemberB{Value: p.Data}},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) ListUserPasskeys(ctx context.Context, serviceID, userID string) ([]UserPasskey, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkUser + serviceID + "#" + userID},
			":s": &types.AttributeValueMemberS{Value: skPasskey},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []userPasskeyItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	keys := make([]UserPasskey, 0, len(items))
	for _, it := range items {
		k, err := it.toPasskey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (d *Dynamo) GetUserPasskeyByCred(ctx context.Context, serviceID, credID string) (UserPasskey, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiUPK + serviceID + "#" + credID}},
		Limit:                     aws.Int32(1),
	})
	if err != nil {
		return UserPasskey{}, err
	}
	if len(out.Items) == 0 {
		return UserPasskey{}, ErrNotFound
	}
	var it userPasskeyItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &it); err != nil {
		return UserPasskey{}, err
	}
	return it.toPasskey()
}

func (d *Dynamo) DeleteUser(ctx context.Context, serviceID, id string) error {
	u, err := d.GetUser(ctx, serviceID, id)
	if err != nil {
		return err
	}
	keys, err := d.ListUserPasskeys(ctx, serviceID, id)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkUser+serviceID+"#"+id, skPasskey+k.ID)}); err != nil {
			return err
		}
	}
	// Seen-IP rows: best effort, they expire on their own anyway.
	q, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkUser + serviceID + "#" + id},
			":sk": &types.AttributeValueMemberS{Value: skSeen},
		},
		ProjectionExpression: aws.String("SK"),
	})
	if err == nil {
		for _, it := range q.Items {
			if sk, ok := it["SK"].(*types.AttributeValueMemberS); ok {
				_, _ = d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkUser+serviceID+"#"+id, sk.Value)})
			}
		}
	}
	// Org memberships: the user must not linger as a member (or admin).
	mems, err := d.ListUserOrgs(ctx, serviceID, id)
	if err != nil {
		return err
	}
	for _, mb := range mems {
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+mb.OrgID, skMember+id)}); err != nil {
			return err
		}
	}
	// Identity lock and user row go together so a half-deleted account can
	// neither sign in nor block re-registration.
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: &d.table, Key: dynKey(pkIdent+serviceID+"#"+u.Identity, skMeta)}},
			{Delete: &types.Delete{TableName: &d.table, Key: dynKey(pkUser+serviceID+"#"+id, skMeta)}},
		},
	})
	return err
}

// ── orgs (auth-service-15) ─────────────────────────────────────────────────

type orgItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ID                     string `dynamodbav:"id"`
	ServiceID              string `dynamodbav:"service_id"`
	Name                   string `dynamodbav:"name"`
	Status                 string `dynamodbav:"status"`
	CreatedAt              string `dynamodbav:"created_at"`
}

func (it orgItem) toOrg() (Org, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return Org{}, fmt.Errorf("store: bad created_at on %s: %w", it.PK, err)
	}
	return Org{ID: it.ID, ServiceID: it.ServiceID, Name: it.Name, Status: it.Status, CreatedAt: t}, nil
}

type memberItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ServiceID              string `dynamodbav:"service_id"`
	OrgID                  string `dynamodbav:"org_id"`
	UserID                 string `dynamodbav:"user_id"`
	Role                   string `dynamodbav:"role"`
	CreatedAt              string `dynamodbav:"created_at"`
}

func (it memberItem) toMember() (OrgMember, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return OrgMember{}, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
	}
	return OrgMember{ServiceID: it.ServiceID, OrgID: it.OrgID, UserID: it.UserID, Role: it.Role, CreatedAt: t}, nil
}

func (d *Dynamo) CreateOrg(ctx context.Context, o Org) error {
	item, err := attributevalue.MarshalMap(orgItem{
		PK: pkOrg + o.ServiceID + "#" + o.ID, SK: skMeta, GSI1PK: gsiOrgs + o.ServiceID, GSI1SK: o.CreatedAt.UTC().Format(time.RFC3339Nano) + "#" + o.ID,
		Type: "org", ID: o.ID, ServiceID: o.ServiceID, Name: o.Name, Status: o.Status, CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetOrg(ctx context.Context, serviceID, id string) (Org, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+id, skMeta)})
	if err != nil {
		return Org{}, err
	}
	if out.Item == nil {
		return Org{}, ErrNotFound
	}
	var it orgItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return Org{}, err
	}
	return it.toOrg()
}

func (d *Dynamo) ListOrgs(ctx context.Context, serviceID string, limit int, cursor string) ([]Org, string, error) {
	in := &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiOrgs + serviceID}},
		Limit:                     aws.Int32(int32(limit + 1)), //nolint:gosec // limit is clamped by the caller
	}
	if cursor != "" {
		gsk, pk, ok := strings.Cut(cursor, "|")
		if !ok {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"GSI1PK": &types.AttributeValueMemberS{Value: gsiOrgs + serviceID}, "GSI1SK": &types.AttributeValueMemberS{Value: gsk},
			"PK": &types.AttributeValueMemberS{Value: pk}, "SK": &types.AttributeValueMemberS{Value: skMeta},
		}
	}
	out, err := d.db.Query(ctx, in)
	if err != nil {
		return nil, "", err
	}
	var items []orgItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].GSI1SK + "|" + items[limit-1].PK
	}
	orgs := make([]Org, 0, len(items))
	for _, it := range items {
		o, err := it.toOrg()
		if err != nil {
			return nil, "", err
		}
		orgs = append(orgs, o)
	}
	return orgs, next, nil
}

func (d *Dynamo) UpdateOrg(ctx context.Context, o Org) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkOrg+o.ServiceID+"#"+o.ID, skMeta),
		UpdateExpression:         aws.String("SET #n = :n, #s = :s"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#n": "name", "#s": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":n": &types.AttributeValueMemberS{Value: o.Name},
			":s": &types.AttributeValueMemberS{Value: o.Status},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) DeleteOrg(ctx context.Context, serviceID, id string) error {
	if _, err := d.GetOrg(ctx, serviceID, id); err != nil {
		return err
	}
	mems, err := d.ListOrgMembers(ctx, serviceID, id)
	if err != nil {
		return err
	}
	for _, mb := range mems {
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+id, skMember+mb.UserID)}); err != nil {
			return err
		}
	}
	invs, err := d.ListOrgInvites(ctx, serviceID, id)
	if err != nil {
		return err
	}
	for _, inv := range invs {
		if _, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+id, skInvite+inv.Email)}); err != nil {
			return err
		}
	}
	_, err = d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+id, skMeta)})
	return err
}

func (d *Dynamo) PutOrgMember(ctx context.Context, m OrgMember) error {
	// Upsert that keeps the original created_at: role changes are not re-joins.
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkOrg+m.ServiceID+"#"+m.OrgID, skMember+m.UserID),
		UpdateExpression:         aws.String("SET #t = :t, service_id = :svc, org_id = :o, user_id = :u, #r = :r, created_at = if_not_exists(created_at, :c), GSI1PK = :g1, GSI1SK = :g2"),
		ExpressionAttributeNames: map[string]string{"#t": "type", "#r": "role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t":   &types.AttributeValueMemberS{Value: "org_member"},
			":svc": &types.AttributeValueMemberS{Value: m.ServiceID},
			":o":   &types.AttributeValueMemberS{Value: m.OrgID},
			":u":   &types.AttributeValueMemberS{Value: m.UserID},
			":r":   &types.AttributeValueMemberS{Value: m.Role},
			":c":   &types.AttributeValueMemberS{Value: m.CreatedAt.UTC().Format(time.RFC3339Nano)},
			":g1":  &types.AttributeValueMemberS{Value: gsiUserOrgs + m.ServiceID + "#" + m.UserID},
			":g2":  &types.AttributeValueMemberS{Value: pkOrg + m.OrgID},
		},
	})
	return err
}

func (d *Dynamo) GetOrgMember(ctx context.Context, serviceID, orgID, userID string) (OrgMember, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+orgID, skMember+userID)})
	if err != nil {
		return OrgMember{}, err
	}
	if out.Item == nil {
		return OrgMember{}, ErrNotFound
	}
	var it memberItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return OrgMember{}, err
	}
	return it.toMember()
}

// queryMembers drains every page of a member query.
func (d *Dynamo) queryMembers(ctx context.Context, in *dynamodb.QueryInput) ([]OrgMember, error) {
	out := []OrgMember{}
	for {
		page, err := d.db.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		var items []memberItem
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			m, err := it.toMember()
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		if page.LastEvaluatedKey == nil {
			break
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
	sortMembers(out)
	return out, nil
}

func (d *Dynamo) ListOrgMembers(ctx context.Context, serviceID, orgID string) ([]OrgMember, error) {
	return d.queryMembers(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkOrg + serviceID + "#" + orgID},
			":sk": &types.AttributeValueMemberS{Value: skMember},
		},
	})
}

func (d *Dynamo) ListUserOrgs(ctx context.Context, serviceID, userID string) ([]OrgMember, error) {
	return d.queryMembers(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiUserOrgs + serviceID + "#" + userID}},
	})
}

func (d *Dynamo) DeleteOrgMember(ctx context.Context, serviceID, orgID, userID string) error {
	_, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+orgID, skMember+userID),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

// ── org invites (auth-service-32) ──────────────────────────────────────────
//
// ORG#<svc>#<org> / INVITE#<email>, GSI1 INVITES#<svc>#<email> / ORG#<org>:
// one query lists an org's pending invites, one index query the invites
// waiting for an address. The table TTL reaps expired rows.

type inviteItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ServiceID              string `dynamodbav:"service_id"`
	OrgID                  string `dynamodbav:"org_id"`
	Email                  string `dynamodbav:"email"`
	Role                   string `dynamodbav:"role"`
	InvitedBy              string `dynamodbav:"invited_by,omitempty"`
	CreatedAt              string `dynamodbav:"created_at"`
	ExpiresAt              string `dynamodbav:"expires_at"`
	TTL                    int64  `dynamodbav:"ttl"`
}

func (it inviteItem) toInvite() (OrgInvite, error) {
	c, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return OrgInvite{}, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
	}
	e, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil {
		return OrgInvite{}, fmt.Errorf("store: bad expires_at on %s/%s: %w", it.PK, it.SK, err)
	}
	return OrgInvite{ServiceID: it.ServiceID, OrgID: it.OrgID, Email: it.Email, Role: it.Role, InvitedBy: it.InvitedBy, CreatedAt: c, ExpiresAt: e}, nil
}

func (d *Dynamo) PutOrgInvite(ctx context.Context, inv OrgInvite) error {
	item, err := attributevalue.MarshalMap(inviteItem{
		PK: pkOrg + inv.ServiceID + "#" + inv.OrgID, SK: skInvite + inv.Email,
		GSI1PK: gsiInvites + inv.ServiceID + "#" + inv.Email, GSI1SK: pkOrg + inv.OrgID,
		Type: "org_invite", ServiceID: inv.ServiceID, OrgID: inv.OrgID, Email: inv.Email, Role: inv.Role, InvitedBy: inv.InvitedBy,
		CreatedAt: inv.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339Nano), TTL: inv.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) GetOrgInvite(ctx context.Context, serviceID, orgID, email string) (OrgInvite, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+orgID, skInvite+email)})
	if err != nil {
		return OrgInvite{}, err
	}
	if out.Item == nil {
		return OrgInvite{}, ErrNotFound
	}
	var it inviteItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return OrgInvite{}, err
	}
	return it.toInvite()
}

// queryInvites drains every page of an invite query.
func (d *Dynamo) queryInvites(ctx context.Context, in *dynamodb.QueryInput) ([]OrgInvite, error) {
	out := []OrgInvite{}
	for {
		page, err := d.db.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		var items []inviteItem
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			inv, err := it.toInvite()
			if err != nil {
				return nil, err
			}
			out = append(out, inv)
		}
		if page.LastEvaluatedKey == nil {
			break
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
	sortInvites(out)
	return out, nil
}

func (d *Dynamo) ListOrgInvites(ctx context.Context, serviceID, orgID string) ([]OrgInvite, error) {
	return d.queryInvites(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkOrg + serviceID + "#" + orgID},
			":sk": &types.AttributeValueMemberS{Value: skInvite},
		},
	})
}

func (d *Dynamo) ListEmailInvites(ctx context.Context, serviceID, email string) ([]OrgInvite, error) {
	return d.queryInvites(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiInvites + serviceID + "#" + email}},
	})
}

func (d *Dynamo) DeleteOrgInvite(ctx context.Context, serviceID, orgID, email string) error {
	_, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &d.table, Key: dynKey(pkOrg+serviceID+"#"+orgID, skInvite+email),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}
