This directory contains the default templates that are used by the rageshake server.

The templates can be overridden via settings in the config file.

The templates are as follows:

* `issue_body.tmpl`: Used when filing an issue at Github or Gitlab, and gives the issue description. Override via
  the `issue_body_template_file` setting in the configuration file.

See https://pkg.go.dev/text/template#pkg-overview for documentation of the template language.

The following properties are defined on the input (accessible via `.` or `$`):

| Name         | Type                | Description                                                                                       |
|--------------|---------------------|---------------------------------------------------------------------------------------------------|
| `ID`         | `string`            | The unique ID for this rageshake.                                                                 |
| `UserText`   | `string`            | A multi-line string containing the user description of the fault (from `text` in the submission). |
| `AppName`    | `string`            | A short slug to identify the app making the report (from `app` in the submission).                |
| `Labels`     | `[]string`          | A list of labels requested by the application.                                                    |
| `Data`       | `map[string]string` | A map of other key/value pairs included in the submission.                                        |
| `Logs`       | `[]string`          | A list of log file names.                                                                         |
| `LogErrors`  | `[]string`          | Set if there are log parsing errors.                                                              |
| `Files`      | `[]string`          | A list of other files (not logs) uploaded as part of the rageshake.                               |
| `FileErrors` | `[]string`          | Set if there are file parsing errors.                                                             |
| `ListingURL` | `string`            | Complete link to the listing URL that contains all uploaded logs.                                 |
