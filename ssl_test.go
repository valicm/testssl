package main

import (
	"testing"
)

func Test_parseDomainName(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name string
		args args
		want string
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				domain: "example.com",
			},
			want: "example.com",
		},
		{
			name: "autotld",
			args: args{
				domain: "example",
			},
			want: "example.test",
		},
		{
			name: "dummytld",
			args: args{
				domain: "pero.zdero",
			},
			want: "pero.zdero",
		},}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDomainName(tt.args.domain); got != tt.want {
				t.Errorf("parseDomainName() = %v, want %v", got, tt.want)
			}
		})
	}
}