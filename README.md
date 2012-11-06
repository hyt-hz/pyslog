pyslog
======

A python script to append and parse syslog in the format of:

Oct 23 00:23:21 localhost ProgramIdent[3011]: [notice] [operation] blablabla

It's fairly straight forward about its log append part, however the parser part has some interesting features:

1. It can parse syslog file as well as its rotated ones
2. The parser works as a generator, it returns one entry per time from the newest log to the oldest one in a dict
3. The parser accepts filter rules like time range, log priority and log type
4. The parser can returns log entry in both dict or string format
4. The parser works in a memory efficient way that it doesn't hold the whole file in memory, so it can be used for huge log file

Though there are still some limitations:

1. Not able to parse gzipped log file
2. Works only for log in the format mentioned above
3. It will ignore logs like "last message repeated x times"
4. Since syslog does not keep track of the year, in order to utilize the time range filter, keep less then one year's log