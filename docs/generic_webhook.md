## Generic webhook request

If the configuration option `generic_webhook_urls` is set, then an asynchronous request to
each endpoint listed will be sent in parallel, after the incoming request is parsed and the
files are uploaded.

The webhook is designed for notification or other tracking services, and does not contain
the original log files uploaded.

(If you want the original log files, we suggest to implement the rageshake interface itself).

A sample JSON body is as follows:

```
{
  'user_text': 'test\r\n\r\nIssue: No issue link given',
  'app': 'element-web',
  'data': {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Version': '0f15ba34cdf5-react-0f15ba34cdf5-js-0f15ba34cdf5',
    ...
    'user_id': '@michaelgoesforawalk:matrix.org'},
  'labels': None,
  'logs': [
    'logs-0000.log.gz',
    'logs-0001.log.gz',
    'logs-0002.log.gz',
  ],
  'logErrors': None,
  'files': [
    'screenshot.png'
  ],
  'fileErrors': None,
  'report_url': 'https://github.com/your-org/your-repo/issues/1251',
  'listing_url': 'http://your-rageshake-server/api/listing/2022-01-25/154742-OOXBVGIX'
}
```

The log and other files can be individually downloaded by concatenating the `listing_url` and the `logs` or `files` name.
You may need to provide a HTTP basic auth user/pass if configured on your rageshake server.
