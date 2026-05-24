package bootstrap

import "testing"

func TestSetConfigValue(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
		value   string
		want    string
	}{
		{
			name:    "replace existing key",
			content: "PermitRootLogin yes\n",
			key:     "PermitRootLogin",
			value:   "no",
			want:    "PermitRootLogin no\n",
		},
		{
			name:    "commented key appends new",
			content: "#PermitRootLogin yes\n",
			key:     "PermitRootLogin",
			value:   "no",
			want:    "#PermitRootLogin yes\n\nPermitRootLogin no",
		},
		{
			name:    "add new key",
			content: "PasswordAuthentication yes\n",
			key:     "MaxAuthTries",
			value:   "3",
			want:    "PasswordAuthentication yes\n\nMaxAuthTries 3",
		},
		{
			name:    "replace with value containing number",
			content: "Port 22\n",
			key:     "Port",
			value:   "2222",
			want:    "Port 2222\n",
		},
		{
			name:    "empty content",
			content: "",
			key:     "Key",
			value:   "val",
			want:    "\nKey val",
		},
		{
			name:    "multiple same key replaces all",
			content: "Key old\nSomething else\nKey old2\n",
			key:     "Key",
			value:   "new",
			want:    "Key new\nSomething else\nKey new\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setConfigValue(tt.content, tt.key, tt.value)
			if got != tt.want {
				t.Errorf("setConfigValue(%q, %q, %q)\n got: %q\nwant: %q",
					tt.content, tt.key, tt.value, got, tt.want)
			}
		})
	}
}
