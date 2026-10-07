package neo4j

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Client wraps the Neo4j driver for Correlic graph storage
type Client struct {
	driver neo4j.DriverWithContext
	uri    string
}

// NewClient creates a new Neo4j client connection
func NewClient(uri, username, password string) (*Client, error) {
	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(username, password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create neo4j driver: %w", err)
	}

	// Verify connectivity
	ctx := context.Background()
	if err := driver.VerifyConnectivity(ctx); err != nil {
		driver.Close(ctx)
		return nil, fmt.Errorf("failed to verify neo4j connectivity: %w", err)
	}

	return &Client{
		driver: driver,
		uri:    uri,
	}, nil
}

// Close closes the Neo4j driver connection
func (c *Client) Close(ctx context.Context) error {
	return c.driver.Close(ctx)
}

// Session creates a new Neo4j session
func (c *Client) Session(ctx context.Context) neo4j.SessionWithContext {
	return c.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
}

// ExecuteRead executes a read query and returns the result
func (c *Client) ExecuteRead(ctx context.Context, query string, params map[string]any) (*neo4j.EagerResult, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		queryResult, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		// Collect all results
		return queryResult.Collect(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("read query failed: %w", err)
	}

	// Result is []*neo4j.Record
	records, ok := result.([]*neo4j.Record)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}

	// Convert to EagerResult
	eagerResult := &neo4j.EagerResult{
		Records: records,
	}

	return eagerResult, nil
}

// ExecuteWrite executes a write query without returning records
func (c *Client) ExecuteWrite(ctx context.Context, query string, params map[string]any) error {
	session := c.Session(ctx)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, query, params)
	})
	if err != nil {
		return fmt.Errorf("write query failed: %w", err)
	}

	return nil
}

// ExecuteWriteWithResult executes a write query and returns the result
func (c *Client) ExecuteWriteWithResult(ctx context.Context, query string, params map[string]any) (*neo4j.EagerResult, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		queryResult, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		// Collect all results
		return queryResult.Collect(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("write query failed: %w", err)
	}

	// Result is []*neo4j.Record
	records, ok := result.([]*neo4j.Record)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}

	// Convert to EagerResult
	eagerResult := &neo4j.EagerResult{
		Records: records,
	}

	return eagerResult, nil
}
