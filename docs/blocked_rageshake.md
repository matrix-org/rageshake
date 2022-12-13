# Rageshake server not accepting rageshakes

This page contains information useful to someone who has had their rageshake rejected by a rageshake server.

We include it within the error messages to provide a place with context for users reading the error message and wanting
to know more.

## For matrix client users

Thank you for attempting to report a bug with your matrix client; unfortunately your client application is likely incorrectly configured.

The rageshake server you attempted to upload a report to is not accepting rageshakes from your client at this time.

Generally, the developers who run a rageshake server will only be able to handle reports for applications they are developing,
and your application is not listed as one of those applications.

Please contact the distributor of your application or the administrator of the web site you visit to report this as a problem.

## For developers of matrix clients

Your application is likely based on one of the matrix SDKs or element applications, if it is submitting rageshakes to a rageshake server.

A change has been made to pre-filter reports that the developers using this rageshake server for applications they do not have control over.
Typically reports from unknown applications would have to be manually triaged and discarded; there is now automatic filtering in place, which reduces overall effort.

There is generally a configuration file in your application that you can alter to change where these reports are sent, which may require rebuilding and releasing the client.

The easiest solution to this error is to stop sending rageshakes entirely, which may require a code or configuration change in your client.

However, if you wish to accept bug reports from your users applications; you will need to run your own copy of this rageshake server and update the URL appropriately.

## Application specific config locations:
 * element-web: `bug_report_endpoint_url` in the [sample configuration for element web](https://github.com/vector-im/element-web/blob/develop/config.sample.json).
 * element-ios: `bugReportEndpointUrlString` in the [BuildSettings.swift](https://github.com/vector-im/element-ios/blob/develop/Config/BuildSettings.swift)
 * element-android: `bug_report_url` in the [config.xml file for the build](https://github.com/vector-im/element-android/blob/develop/vector-config/src/main/res/values/config.xml)
