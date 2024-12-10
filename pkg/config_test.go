package pkg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/dealancer/validate.v2"
)

func TestEmptyConfigs(t *testing.T) {
	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Error(err)
	}

	validate.Validate(config)
}

func TestBase64StringParse(t *testing.T) {
	type TestStruct struct {
		Foo Base64String
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: base64StringDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	testValueBase64String := "KJR4EeL83nexOFihmdYciri7Mo7ciAq/b5/S0lREcns="
	testValueBytes, err := base64.StdEncoding.DecodeString(testValueBase64String)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Foo": testValueBase64String,
	}

	decoder.Decode(input)

	if reflect.DeepEqual(testValueBytes, output.Foo) {
		t.Error("No match")
	}
}

func TestSensitiveBase64StringParse(t *testing.T) {
	type TestStruct struct {
		Foo SensitiveBase64String
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: base64StringDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	testValueBase64String := "KJR4EeL83nexOFihmdYciri7Mo7ciAq/b5/S0lREcns="
	testValueBytes, err := base64.StdEncoding.DecodeString(testValueBase64String)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Foo": testValueBase64String,
	}

	decoder.Decode(input)

	if reflect.DeepEqual(testValueBytes, output.Foo) {
		t.Error("No match")
	}

	if output.Foo.String() != RedactedString {
		t.Error("String value should have been redacted")
	}
}

func TestBitSetStringParse(t *testing.T) {
	bsGet := ParseHttpMethods([]string{"GET"})

	if bsGet.Test(MethodGet) != true {
		t.Fail()
	}
	if bsGet.Test(MethodPost) != false {
		t.Fail()
	}
	if bsGet.Test(MethodDelete) != false {
		t.Fail()
	}

	bsGetPost := ParseHttpMethods([]string{"GET", "POST"})
	if bsGetPost.Test(MethodGet) != true {
		t.Fail()
	}
	if bsGetPost.Test(MethodPost) != true {
		t.Fail()
	}
	if bsGetPost.Test(MethodDelete) != false {
		t.Fail()
	}
}

func TestHttpMethodsDecodeHook(t *testing.T) {
	type TestStruct struct {
		Methods HttpMethods
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: httpMethodsDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Methods": []string{"GET", "POST"},
	}

	decoder.Decode(input)

	expected := BitSet(0)
	expected.Set(MethodGet)
	expected.Set(MethodPost)

	if output.Methods != HttpMethods(expected) {
		t.Error(fmt.Errorf("No match: %+v != %+v", output.Methods, expected))
	}
}

func TestGitHubGraphQLValidation(t *testing.T) {
	config := &InboundProxyConfig{}
	filter := &GitHubGraphQLFilter{
		AllowedOperations: map[string][]string{
			"query":    {"GetRepository", "GetPullRequest"},
			"mutation": {"CreateIssue"},
		},
	}

	tests := []struct {
		name        string
		request     githubGraphQLRequest
		shouldError bool
		errorMsg    string
	}{
		{
			name: "valid query operation",
			request: githubGraphQLRequest{
				Query: `query GetRepository { 
                    repository(owner: "owner", name: "name") { 
                        id 
                    }
                }`,
				OperationName: "GetRepository",
			},
			shouldError: false,
		},
		{
			name: "valid query operation no operation name",
			request: githubGraphQLRequest{
				Query: `query GetRepository { 
                    repository(owner: "owner", name: "name") { 
                        id 
                    }
                }`,
			},
			shouldError: false,
		},
		{
			name: "valid mutation operation",
			request: githubGraphQLRequest{
				Query: `mutation CreateIssue { 
                    createIssue(input: {repositoryId: "123", title: "title"}) { 
                        issue { id } 
                    }
                }`,
				OperationName: "CreateIssue",
			},
			shouldError: false,
		},
		{
			name: "operation not in allowlist",
			request: githubGraphQLRequest{
				Query: `query GetUser { 
                    user(login: "username") { 
                        id 
                    }
                }`,
				OperationName: "GetUser",
			},
			shouldError: true,
			errorMsg:    "GitHub GraphQL query operation 'GetUser' not allowed",
		},
		{
			name: "operation type not allowed",
			request: githubGraphQLRequest{
				Query: `subscription WatchRepository { 
                    repository { 
                        id 
                    }
                }`,
				OperationName: "WatchRepository",
			},
			shouldError: true,
			errorMsg:    "GitHub GraphQL operation type 'subscription' not allowed",
		},
		{
			name: "unnamed operation",
			request: githubGraphQLRequest{
				Query: `query { 
                    repository(owner: "owner", name: "name") { 
                        id 
                    }
                }`,
			},
			shouldError: true,
			errorMsg:    "GitHub GraphQL operations must be named",
		},
		{
			name: "operation name mismatch",
			request: githubGraphQLRequest{
				Query: `query GetRepository { 
                    repository(owner: "owner", name: "name") { 
                        id 
                    }
                }`,
				OperationName: "DifferentName",
			},
			shouldError: true,
			errorMsg:    "operation name mismatch between request and query",
		},
		{
			name: "invalid GraphQL syntax",
			request: githubGraphQLRequest{
				Query: `query GetRepository { 
                    repository(owner: "owner", name: "name") { 
                        id 
                    `, // Missing closing brace
				OperationName: "GetRepository",
			},
			shouldError: true,
			errorMsg:    "graphql query is unparseable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			err = config.validateGitHubGraphQLRequest(requestBody, filter)

			if tt.shouldError {
				if err == nil {
					t.Error("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q but got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGitHubGraphQLValidationWithNilFilter(t *testing.T) {
	config := &InboundProxyConfig{}
	request := githubGraphQLRequest{
		Query: `query GetRepository { 
            repository(owner: "owner", name: "name") { 
                id 
            }
        }`,
		OperationName: "GetRepository",
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	err = config.validateGitHubGraphQLRequest(requestBody, nil)
	if err != nil {
		t.Errorf("expected no error with nil filter but got: %v", err)
	}
}
