# Common report styles.

Rageshakes can come from a number of applications, and we provide some practical notes on the generated format.

At present these should not be considered absolute nor a structure to follow; but an attempt to document the
currently visible formats as of January 2022


## Feedback 

Log files are not transmitted, the main feedback is entirely within the user message body.

## Element Web

Log files are transmitted in reverse order (0000 is the youngest) 

Log line format:
```
2022-01-17T14:57:20.806Z I Using WebAssembly Olm
< ---- TIMESTAMP ------> L <-- Message ----

L = log level, (W=Warn, I=Info, etc)
```

New log files are started each restart of the app.


## Element desktop



## Element iOS

Crash Log is special and is sent only once (and deleted on the device afterwards)

`crash.log`



Following logs are available, going back in time with ascending number.
console.log with no number is the current log file.
```
console.log (newest)
console-1.log 
...
console-49.log (oldest)

console-nse.log (newest)
console-nse-1.log 
...
console-nse-49.log (oldest)

console-share.log (newest)
console-share-1.log
console-share-49.log (oldest)
```

## Element Android

Log file 0000 is special and 

Log line format:
```
01-17 14:59:30.657 14303 14303 W Activity: Slow Operation: 
<-- TIMESTAMP ---> <-?-> <-?-> L <-- Message --

L = Log Level (W=Warn, I=Info etc)
```


Remaining log files are transmitted according to their position in the round-robin logging to file - there will be (up to) 7 files written to in a continious loop; one of the seven will be the oldest, the rest will be in order.

New log files are started every 30Mb or restart of the app.

Log line format:
```
2022-01-17T13:06:36*838GMT+00:00Z 12226 D/ /Tag: Migration: Importing legacy session
< ---- TIMESTAMP ---------------> <-?-> L        <-- Message ----

L = log level, (W=Warn, I=Info, etc)
```



