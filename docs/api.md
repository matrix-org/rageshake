## Error responses

The rageshake server will respond with a specific JSON payload on error:

```json
{
    "error": "A human readable error string.",
    "errcode": "RS_UNKNOWN",
    "policy_url": "https://github.com/matrix-org/rageshake/blob/master/docs/blocked_rageshake.md"
}
```

Where the fields are as follows:

 - `error` is an error string to explain the error, in English.
 - `errcode` is a machine readable error code which can be used by clients to give a localized error.
 - `policy_url` is an optional URL that links to a reference document, which may be presented to users.

### Error codes

- `RS_UNKNOWN` is a catch-all error when the appliation does not have a specific error.
- `RS_METHOD_NOT_ALLOWED` is reported when you have used the wrong method for a service. E.g. GET instead of POST.
- `RS_DISALLOWED_APP` is reported when a report was rejected due to the report being sent from an unsupported
   app (see the `allowed_app_names` config option).
- `RS_BAD_HEADER` is reported when a header was not able to be parsed, such as `Content-Length`.
- `RS_CONTENT_TOO_LARGE` is reported when the reported content size is too large.
- `RS_BAD_CONTENT` is reported when the reports content could not be parsed.
- `RS_REJECTED` is is reported when the submission could be understood but was rejected by `rejection_conditions`.
  This is the default value, see below for more information.

In addition to these error codes, the configuration allows application developers to specify specific error codes
for report rejection (see the `rejection_conditions` config option). Consult the administrator of your rageshake
server in order to determine what error codes may be presented.
