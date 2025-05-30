package main

import "testing"

func TestConfigRejectionCondition(t *testing.T) {
	cfg := config{
		RejectionConditions: []RejectionCondition{
			{
				App:     "my-app",
				Version: "0.1.0",
			},
			{
				App:   "my-app",
				Label: "0.1.1",
			},
			{
				App:     "my-app",
				Version: "0.1.2",
				Label:   "nightly",
				Reason:  "no nightlies",
				ErrorCode: "BAD_VERSION",
			},
			{
				App: "block-my-app",
			},
			{
				UserTextMatch: "(\\w{4}\\s){11}\\w{4}",
				Reason:        "it matches a recovery key and recovery keys are private",
				ErrorCode: "EXPOSED_RECOVERY_KEY",
			},
		},
	}
	rejectPayloads := []payload{
		{
			AppName: "my-app",
			Data: map[string]string{
				"Version": "0.1.0",
				// Hack add how we expect the rageshake to be rejected to the test
				// The actual data in a rageshake has no ExpectedRejectReason field
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
		},
		{
			AppName: "my-app",
			Data: map[string]string{
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
			Labels: []string{"0.1.1"},
		},
		{
			AppName: "my-app",
			Labels:  []string{"foo", "nightly"},
			Data: map[string]string{
				"Version":              "0.1.2",
				"ExpectedRejectReason": "no nightlies",
				"ExpectedErrorCode": "BAD_VERSION",
			},
		},
		{
			AppName: "block-my-app",
			Data: map[string]string{
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
		},
		{
			AppName: "block-my-app",
			Labels:  []string{"foo"},
			Data: map[string]string{
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
		},
		{
			AppName: "block-my-app",
			Data: map[string]string{
				"Version":              "42",
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
		},
		{
			AppName: "block-my-app",
			Labels:  []string{"foo"},
			Data: map[string]string{
				"Version":              "42",
				"ExpectedRejectReason": "app or user text rejected",
				"ExpectedErrorCode": ErrCodeRejected,
			},
		},
		{
			AppName:  "my-app",
			UserText: "Looks like a recover key abcd abcd abcd abcd abcd abcd abcd abcd abcd abcd abcd abcd",
			Data: map[string]string{
				"ExpectedRejectReason": "it matches a recovery key and recovery keys are private",
				"ExpectedErrorCode": "EXPOSED_RECOVERY_KEY",
			},
		},
	}
	for _, p := range rejectPayloads {
		reject, code := cfg.matchesRejectionCondition(&p)
		if reject == nil || code == nil {
			t.Errorf("payload was accepted when it should be rejected:\n payload=%+v\nconfig=%+v", p, cfg)
		}
		if reject != nil {
			if *reject != p.Data["ExpectedRejectReason"] {
				t.Errorf("payload was rejected with the wrong reason:\n payload=%+v\nconfig=%+v", p, cfg)
			}
		}
		if code != nil {
			if *code != p.Data["ExpectedErrorCode"] {
				t.Errorf("payload was rejected with the wrong code:\n payload=%+v\nconfig=%+v\ncode=%s", p, cfg, *code)
			}
		}
	}
	acceptPayloads := []payload{
		{
			AppName: "different-app",
			Data: map[string]string{
				"Version": "0.1.0",
			},
		},
		{
			AppName: "different-app",
			Data:    map[string]string{},
			Labels:  []string{"0.1.1"},
		},
		{
			AppName: "different-app",
			Labels:  []string{"foo", "nightly"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
		{
			AppName: "my-app",
			Data: map[string]string{
				"Version": "0.1.0-suffix",
			},
		},
		{
			AppName: "my-app",
			Data:    map[string]string{},
			Labels:  []string{"0.1.1-suffix"},
		},
		{
			AppName: "my-app",
			Labels:  []string{"foo", "nightly-suffix"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
		{ // version matches but label does not (it's Label AND Version not OR)
			AppName: "my-app",
			Labels:  []string{"foo"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
		{
			AppName:  "my-app",
			UserText: "Some description",
		},
	}
	for _, p := range acceptPayloads {
		reject, code := cfg.matchesRejectionCondition(&p)
		if reject != nil || code != nil {
			t.Errorf("payload was rejected when it should be accepted:\n payload=%+v\nconfig=%+v", p, cfg)
		}
	}
}
