import syslog
from datetime import datetime


class Log(object):
    # log level
    LEVEL_EMERG = syslog.LOG_EMERG
    LEVEL_ALERT = syslog.LOG_ALERT
    LEVEL_CRIT = syslog.LOG_CRIT
    LEVEL_ERR = syslog.LOG_ERR
    LEVEL_WARNING = syslog.LOG_WARNING
    LEVEL_NOTICE = syslog.LOG_NOTICE
    LEVEL_INFO = syslog.LOG_INFO
    LEVEL_DEBUG = syslog.LOG_DEBUG
    # log type
    TYPE_OP = 0
    TYPE_EXCEPTION = 1
    TYPE_GENERAL = 2
    # maps
    _level2str_map = {LEVEL_EMERG: "emergency",
                      LEVEL_ALERT: "alert",
                      LEVEL_CRIT: "critical",
                      LEVEL_ERR: "error",
                      LEVEL_WARNING: "warning",
                      LEVEL_NOTICE: "notice",
                      LEVEL_INFO: "info",
                      LEVEL_DEBUG: "debug"}
    _str2level_map = {value: key for key, value in _level2str_map.iteritems()}
    _type2str_map = {TYPE_OP: "operation",
                     TYPE_EXCEPTION: "exception",
                     TYPE_GENERAL: "general"}
    _str2type_map = {value: key for key, value in _type2str_map.iteritems()}
    DEFAULT_LEVEL = LEVEL_INFO
    DEFAULT_TYPE = TYPE_GENERAL
    
    def __init__(self, ident, min_level=LEVEL_INFO):
        self.set_min_level(min_level)
        self.ident = ident;
        
    def level2str(self, level):
        if level in self._level2str_map:
            return self._level2str_map[level]
        else:
            return self.DEFAULT_LEVEL
        
    def str2level(self, string, default=None):
        if string not in self._str2level_map:
            if default is None:
                raise LogUnkownLevelException()
            else:
                return default
        else:
            return self._str2level_map[string]
        
    def not_lower_level(self, level_src, level_dst):
        '''
        return True if level_src is higher or equal than level_dst
        '''
        if not isinstance(level_src, int):
            level_src = self.str2level(level_src)
        if not isinstance(level_dst, int):
            level_dst = self.str2level(level_dst)
        return level_src <= level_dst
        
    def str2type(self, string, default=None):
        '''
        convert log type string to int
        if not found, raise exception or return default value given by default
        '''
        if string not in self._str2type_map:
            if default is None:
                raise LogUnkownTypeException()
            else:
                return default
        else:
            return self._str2type_map[string]
        
    def is_same_type(self, type_src, type_dst):
        if not isinstance(type_src, int):
            type_src = self.str2type(type_src)
        if not isinstance(type_dst, int):
            type_dst= self.str2type(type_dst)
        return type_src == type_dst
        
    def set_min_level(self, min_level):        
        if min_level not in self._level2str_map:
            self.min_level = self.DEFAULT_LEVEL
        else:
            self.min_level = min_level
            
    def append(self, msg, level=None, log_type=None):
        if level is None or level not in self._level2str_map:
            level=self.DEFAULT_LEVEL
        level_str = self._level2str_map[level]
        if log_type is None or type not in self._type2str_map:
            log_type = self.TYPE_OP
        type_str = self._type2str_map[log_type]
        if level <= self.min_level:
            syslog.openlog(ident=self.ident, logoption=syslog.LOG_PID|syslog.LOG_NDELAY|syslog.LOG_NOWAIT, facility=syslog.LOG_LOCAL2)
            syslog.syslog(level, "[{0}] [{1}] {2}".format(level_str, type_str, msg))
            syslog.closelog()

    def parse_entry(self, entry):
        info = {}
        if "last message repeated" in entry:
            '''
            parts = entry.split(None, 4)
            if len(parts) < 5:
                raise Exception()
            info['time'] = " ".join(parts[:3])
            info['host'] = parts[3]
            info['msg'] = parts[4]
            '''
            raise Exception()
        else:
            parts = entry.split(None, 7)
            if len(parts) < 8:
                raise Exception()
            info['time'] = " ".join(parts[:3])
            info['host'] = parts[3]
            info['program'], info['pid'] = parts[4].split("[")
            info['pid'], tmp = info['pid'].split("]")
            info['level_str'] = parts[5][1:-1]
            info['level'] = self.str2level(info['level_str'], default=self.DEFAULT_LEVEL)
            info['type_str'] = parts[6][1:-1]
            info['type'] = self.str2type(info['type_str'], default=self.DEFAULT_TYPE)
            info['msg'] = parts[7]
        return info
    
    
    
class LogFinder(Log):
    MAX_ENTRY_NBR = 10000
    
    def __init__(self, log_path):
        self.log_path = log_path
        self.now = datetime.now()
        
    def find(self, start_index=0, limit=0, min_level=None, log_type=None, keyword=None, start_time=None, end_time=None, is_raw=False):
        match_cnt = 0
        nbr_in_list = 0
        entries = []
        if limit > self.MAX_ENTRY_NBR or limit == 0:
            limit = self.MAX_ENTRY_NBR
            
        with LogFiles(self.log_path) as log_files:
            for entry in log_files:
                entry = entry.strip()
                try:
                    entry_info = self.parse_entry(entry)
                except Exception:
                    continue
                
                # filter
                if min_level is not None:
                    if self.not_lower_level(entry_info['level'], min_level):
                        pass
                    else:
                        continue
                if log_type is not None:
                    if self.is_same_type(entry_info['type'], log_type):
                        pass
                    else:
                        continue
                if keyword is not None:
                    if keyword.upper() in entry_info['msg'].upper():
                        pass
                    else:
                        continue
                if start_time is not None:
                    if self.later_than(entry_info['time'], start_time):
                        pass
                    else:
                        break                
                if end_time is not None:
                    if self.later_than(entry_info['time'], end_time):
                        continue
                    else:
                        pass
                
                # match entry found
                match_cnt += 1
                if nbr_in_list < limit and match_cnt > start_index:
                    nbr_in_list += 1
                    if is_raw is True:
                        if len(entries) > 0:
                            entries[0] += entry + '\n'
                        else:
                            entries.append(entry + '\n')
                    else:
                        entries.append(entry_info)
            
        return match_cnt, entries
                
    def parse_log_timestamp(self, log_timestamp):
        '''
        return datetime object corresponding to the given log_timestamp
        log_timestamp string in syslog time-stamp format, e.g. sep 12 21:36:18
        without year information, we need to fill it manually,
        assume we have log no more than 1 year, thus if month+date is later than today, then it must be last year's log   
        '''
        time = datetime.strptime(log_timestamp, "%b %d %H:%M:%S")
        if time.month > self.now.month:
            return time.replace(year=self.now.year-1)
        elif time.month == self.now.month:
            if time.day > self.now.day:
                return time.replace(year=self.now.year-1)
        return time.replace(year=self.now.year)
    
    def later_than(self, log_timestamp, ref_dt):
        '''
        log_timestamp is string in syslog time-stamp format
        ref_dt is the datetime object as the reference
        return True if log_timestamp is later than the reference time, otherwise return False
        '''
        log_dt = self.parse_log_timestamp(log_timestamp)
        return log_dt >= ref_dt


class ReverseReadFile(object):
    '''
    Iterator:
    iterate through file line by line from the end to the beginning
    '''    
    SEARCH_SIZE = 512
    
    def __init__(self, f):
        self.f = f
    
    def __iter__(self):
        self.buf = ''
        self.f.seek(-1, 2)
        self.pos = self.f.tell()
        return self

    def next(self):
        newline_pos = self.buf.rfind('\n')
        if newline_pos != -1:
            line = self.buf[newline_pos+1:]
            self.buf = self.buf[:newline_pos]
            line += '\n'
            return line
        elif self.pos:
            to_read = min(self.SEARCH_SIZE, self.pos)
            self.f.seek(self.pos-to_read)
            self.pos = self.f.tell()
            self.buf = self.f.read(to_read)+self.buf
            if self.pos == 0:
                self.buf = '\n' + self.buf
            return self.next()
        else:
            raise StopIteration


class LogFiles(object):
    '''
    log file class which can hold <log_file> and up to 10 of its rotated log files
    It is also an iterator which can be used to iterate through all logs entry by entry from the newest to the latest
    Currently it supports only non-compressed rotated-log file, due to python's limited support of gz file's negtive seek functionality
    '''    
    def __init__(self, log_file):
        self.file_list = []
        for i in range(10):
            file_info = {}
            try:
                if i == 0:
                    file_name = log_file
                else:
                    file_name = '{0}.{1}'.format(log_file, i)
                file_info['fd'] = open(file_name, 'r')
                file_info['file_name'] = file_name
                #file_info['line_cnt'] = self._line_cnt(file_info['fd'])
                self.file_list.append(file_info)
            except IOError:
                continue
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_value, traceback):
        for f in self.file_list:
            f['fd'].close()
    
    def _line_cnt(self, fd):
        '''
        count line number of given file descriptor
        '''
        i = None
        for i, line in enumerate(fd):
            pass
        if i is None:
            return 0
        else:
            return i+1
    
    def __iter__(self):
        self._file_iter = iter([ReverseReadFile(file_info['fd']) for file_info in self.file_list])
        self._line_iter = None
        return self

    def next(self):
        try:
            if self._line_iter is None:
                self._line_iter = self._file_iter.next().__iter__()
            return self._line_iter.next()
        except StopIteration:
            self._line_iter = self._file_iter.next().__iter__()
            return self.next()


class LogException(Exception):
    code = 6000
    message = "parameter check error"
    detail = None
    
    def __init__(self):
        self.err = self.message

    def __str__(self):
        return '{0}\nerror: {1}\n{2}'.format(self.message, self.code, self.err)
    
    def response(self):
        return {'status': {'code': self.code, 'message': str(self)}}
    
class LogFileNotFoundException(LogException):
    code = 6001
    message = "log file not found"

class LogUnkownLevelException(LogException):
    code = 6010
    message = "unkown log level"
    
    
class LogUnkownTypeException(LogException):
    code = 6011
    message = "unknown log type"


