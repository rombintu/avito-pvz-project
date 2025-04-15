package config

import "testing"

func TestGetOrDefault(t *testing.T) {
	type args struct {
		key          string
		defaultValue string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "default",
			args: args{key: "test", defaultValue: "default"},
			want: "default",
		},
		{
			name: "miss",
			args: args{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetOrDefault(tt.args.key, tt.args.defaultValue); got != tt.want {
				t.Errorf("GetOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}
