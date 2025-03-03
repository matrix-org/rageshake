package main
const (
	// ErrCodeBadContent is reported when the reports content could not be parsed.
	ErrCodeBadContent = "RS_BAD_CONTENT";
	// ErrCodeBadHeader is reported when a header was not able to be parsed.
	ErrCodeBadHeader = "RS_BAD_HEADER";
	// ErrCodeContentTooLarge is reported when the reported content size is too large.
	ErrCodeContentTooLarge = "RS_CONTENT_TOO_LARGE";
	// ErrCodeDisallowedApp is reported when a report was rejected due to the report being sent from an unsupported
	ErrCodeDisallowedApp = "RS_DISALLOWED_APP";
	// ErrCodeMethodNotAllowed is reported when you have used the wrong method for an endpoint.
	ErrCodeMethodNotAllowed = "RS_METHOD_NOT_ALLOWED";
	// ErrCodeRejected is reported when the submission could be understood but was rejected by RejectionConditions.
	ErrCodeRejected = "RS_REJECTED";
	// ErrCodeUnknown is a catch-all error when the appliation does not have a specific error.
	ErrCodeUnknown = "RS_UNKNOWN";
)