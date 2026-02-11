package webhook

import (
	"reflect"
	"testing"
)

func TestExtractSecretsFromWorkflow(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "single secret",
			yaml: `password: ${{ secrets.DOCKER_PASSWORD }}`,
			want: []string{"DOCKER_PASSWORD"},
		},
		{
			name: "multiple secrets",
			yaml: `
          username: ${{ secrets.REGISTRY_USER }}
          password: ${{ secrets.REGISTRY_PASS }}
          token: ${{ secrets.DEPLOY_TOKEN }}`,
			want: []string{"DEPLOY_TOKEN", "REGISTRY_PASS", "REGISTRY_USER"},
		},
		{
			name: "deduplicated",
			yaml: `
          step1: ${{ secrets.MY_SECRET }}
          step2: ${{ secrets.MY_SECRET }}`,
			want: []string{"MY_SECRET"},
		},
		{
			name: "GITHUB_TOKEN excluded",
			yaml: `
          token: ${{ secrets.GITHUB_TOKEN }}
          key: ${{ secrets.DEPLOY_KEY }}`,
			want: []string{"DEPLOY_KEY"},
		},
		{
			name: "only GITHUB_TOKEN",
			yaml: `token: ${{ secrets.GITHUB_TOKEN }}`,
			want: nil,
		},
		{
			name: "no secrets",
			yaml: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest`,
			want: nil,
		},
		{
			name: "spaces in expression",
			yaml: `token: ${{  secrets.SPACED_SECRET  }}`,
			want: []string{"SPACED_SECRET"},
		},
		{
			name: "underscore and numbers in name",
			yaml: `key: ${{ secrets.AWS_ACCESS_KEY_2 }}`,
			want: []string{"AWS_ACCESS_KEY_2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSecretsFromWorkflow([]byte(tt.yaml))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractSecretsFromWorkflow() = %v, want %v", got, tt.want)
			}
		})
	}
}
