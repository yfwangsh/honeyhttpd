import datetime
import logging
import sys
import re
import json

class AccessLogger(object):
    def reskeys(self):
        return  {
                'asctime': 's',
                'filename': 's',
                'funcName': 's',
                'levelname': 's',
                'levelno': 's',	
                'lineno': 'd',
                'module': 's',
                'message': 's',
                'name': 's',
                'process':	'd',	
                'processName': 's',
                'thread': 'd',
                'threadName': 'd'
        }
    def __init__(self, config):
        #fmtstr = config['format']
        #self.extra_keys = re.findall(r'%[(](.*?)[)]', fmtstr)
        fmtstr="%(asctime)s: %(message)s"
        fmt = logging.Formatter(fmtstr)
        #fmt = logging.Formatter("%(asctime)s - %(name)s - %(ip)s - %(username)s - %(message)s")
        loghandler = logging.FileHandler(config['file'])
        loghandler.setFormatter(fmt)
        self.logger = logging.getLogger("access")
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(loghandler)       

    def stores_large(self):
        return False

    def log(self, remote_ip, remote_port, is_ssl, port, request, response, extra={}):
        '''
        extra_dic = {}
        for key in self.extra_keys:
            value = '-'
            if key in self.reskeys().keys():
                continue
            if extra.get(key):
                value = extra.get(key)
            if key == 'remote_port':
                value = str(remote_port) 
            extra_dic[key] = value                        
        self.logger.DEBUG("", extra=extra_dic)
        '''
        body={
            "time": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "port": port,
            "request": str(request),
            "responselen": len(str(response))
        }
        self.logger.debug(json.dumps(body))