from honeyhttpd.lib.server import Server
import requests
import urllib.parse
import memcache
import sys
import os
import re
import uuid
import honeyhttpd.lib.encode as encode
class Lightproxy(Server):

    # Name of the server
    def name(self):
        return "Nginx"

    # Version of the server
    def version(self):
        return "1.15.12"

    # The system of the server to fake
    def system(self):
        return "(Ubuntu)"

    # The value placed in the "Server" header
    def server_version(self):
        return self.name() + "/" + self.version()

    # Mapping of HTTP codes to template messages
    def responses(self):
        return {
                200: ('OK', 'Request fulfilled, document follows'), 
                201: ('Created', 'Document created, URL follows'), 
                202: ('Accepted', 'Request accepted, processing continues off-line'), 
                203: ('Non-Authoritative Information', 'Request fulfilled from cache'), 
                204: ('No Content', 'Request fulfilled, nothing follows'), 
                205: ('Reset Content', 'Clear input form for further input.'), 
                206: ('Partial Content', 'Partial content follows.'), 
                400: ('Bad Request', "Your browser sent a request that this server could not understand."), 
                401: ('Unauthorized', "This server could not verify that you\nare authorized to access the document\nrequested.  Either you supplied the wrong\ncredentials (e.g., bad password), or your\nbrowser doesn't understand how to supply\nthe credentials required."), 
                402: ('Payment Required', ''), 
                403: ('Forbidden', "You don't have permission to access $path\non this server."), 
                404: ('Not Found', 'The requested URL $path was not found on this server.'), 
                405: ('Method Not Allowed', "The requested method $method is not allowed for the URL $path."), 
                406: ('Not Acceptable', "An appropriate representation of the requested resource $path could not be found on this server."), 
                407: ('Proxy Authentication Required', "This server could not verify that you\nare authorized to access the document\nrequested.  Either you supplied the wrong\ncredentials (e.g., bad password), or your\nbrowser doesn't understand how to supply\nthe credentials required."), 
                408: ('Request Timeout', "Server timeout waiting for the HTTP request from the client."), 
                409: ('Conflict', ''), 
                410: ('Gone', "The requested resource<br />$path<br />\nis no longer available on this server and there is no forwarding address.\nPlease remove all references to this resource."), 
                411: ('Length Required', "A request of the requested method $method requires a valid Content-length."), 
                412: ('Precondition Failed', "The precondition on the request for the URL $path evaluated to false."), 
                413: ('Request Entity Too Large', "The requested resource<br />$path<br />\ndoes not allow request data with $method requests, or the amount of data provided in\nthe request exceeds the capacity limit."), 
                414: ('Request-URI Too Long', "The requested URL's length exceeds the capacity\nlimit for this server."), 
                415: ('Unsupported Media Type', "The supplied request data is not in a format\nacceptable for processing by this resource."), 
                416: ('Requested Range Not Satisfiable', 'None of the range-specifier values in the Range\nrequest-header field overlap the current extent\nof the selected resource.'), 
                417: ('Expectation Failed', 'Expect condition could not be satisfied.'), 
                423: ('Locked', "The requested resource is currently locked.\nThe lock must be released or proper identification\ngiven before the method can be applied."), 
                424: ('Failed Dependency', "The method could not be performed on the resource\nbecause the requested action depended on another\naction and that other action failed."), 
                426: ('Upgrade Required', "The requested resource can only be retrieved\nusing SSL.  The server is willing to upgrade the current\nconnection to SSL, but your client doesn't support it.\nEither upgrade your client, or try requesting the page\nusing https://\n"), 
                100: ('Continue', 'Request received, please continue'), 
                101: ('Switching Protocols', 'Switching to new protocol; obey Upgrade header'), 
                300: ('Multiple Choices', 'Object has several resources -- see URI list'), 
                301: ('Moved Permanently', "The document has moved <a href=\"$extra\">here</a>."), 
                302: ('Found', "The document has moved <a href=\"$extra\">here</a>."), 
                303: ('See Other', "The document has moved <a href=\"$extra\">here</a>."), 
                304: ('Not Modified', 'Document has not changed since given time'), 
                305: ('Use Proxy', "This resource is only accessible through the proxy\n$extra<br />\nYou will need to configure your client to use that proxy."), 
                307: ('Temporary Redirect', "The document has moved <a href=\"$extra\">here</a>."), 
                500: ('Internal Server Error', "The server encountered an internal error or\nmisconfiguration and was unable to complete\nyour request.</p>\n<p>Please contact the server administrator at \n $extra to inform them of the time this error occurred,\n and the actions you performed just before this error.</p>\n<p>More information about this error may be available\nin the server error log."), 
                501: ('Not Implemented', "$method to $path not supported."), 
                502: ('Bad Gateway', "The proxy server received an invalid\nresponse from an upstream server."), 
                503: ('Service Unavailable', "The server is temporarily unable to service your\nrequest due to maintenance downtime or capacity\nproblems. Please try again later."), 
                504: ('Gateway Timeout', 'The gateway server did not receive a timely response'), 
                505: ('HTTP Version Not Supported', 'Cannot fulfill request.')}

    def default_headers(self):
        return []

    def error_format(self, port):
        return """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>$code $message</title>
</head><body>
<h1>$message</h1>
<p>$description<br />
</p>\n
<hr>
<address>""" + self.server_version() + " " + self.system() + """ Server at """ + self._domain_name + """ Port """ + str(port) + """</address>
</body></html>

"""
    # Called on any form of request. Return None, None if you wish to continue normally, or return ERROR_CODE, EXTRA
    def on_request(self, handler):
        xfw = handler.headers.get("X-Forwarded-For", failobj='')
        if self._mc and not xfw=='':
            banips = self._memcache.get("LightProxyIPBAN")
            if banips and xfw in banips:
                return 400, ""
        if not handler.path.startswith("/"):
            return 400, ""
        uuns = handler.path + xfw + str(uuid.uuid4())
        reqid = str(uuid.uuid5(uuid.NAMESPACE_URL, uuns))
        handler.headers.add_header("Lgtpxy_UUID", reqid)
        return None, None

    def __init__(self, domain_name, port, timeout, queue, loggers, ssl_cert=None, config=None):
        super(Lightproxy, self).__init__(domain_name, port, timeout, queue, loggers, ssl_cert, config)
        if "targetURL" not in config:
            print("config is not complete set for Lightproxy")
            sys.exit(3)
        self._dstURL = self._config['targetURL']
        if self._config['memcacheURL']:         
            self._memcache = memcache.Client([self._config['memcacheURL']])
            self._mc = True
        self._white = self._config['wlsuffix']
        self._mc=False


    def prepareData(self, path, headers):
        hdpl = {}
        safepath = ''
        queryparam = {}
        print("prepare data, headers:" + str(headers))
        try:
            urlPath= self._dstURL + path
            rtarget = urllib.parse.urlsplit(urlPath)
            npath = rtarget.path
            nquery = rtarget.query
            safereq = False
            safeloc =re.sub('[^a-zA-Z0-9./\-_]',"",npath)
            safepath = self._dstURL + safeloc

            for wb in self._white:
                if npath.endswith(wb):
                    safereq = True
                    break
            if nquery:
                safequery = re.sub('[^a-zA-Z0-9\-_%=&]',"",nquery)
                if safereq:
                    queryparam = urllib.parse.parse_qs(nquery)
                else:
                    queryparam = urllib.parse.parse_qs(safequery)
            for head in headers:
                value = head[1]
                if head[0] == 'Host':
                    value = rtarget.netloc
                elif head[0] == 'Lgtpxy_UUID':
                    continue
                elif head[0] == 'Connection' or \
                    head[0] == 'Accept-Encoding' or \
                    head[0] == 'Accept-Language':
                    pass
                elif head[0] == 'Referer':
                    refers = urllib.parse.urlsplit(head[1])
                    value = urllib.parse.urlunsplit((refers.scheme,refers.netloc, refers.path, "", refers.fragment))
                elif head[0] == 'Cookie':
                    pass                 
                else:
                    if safereq:
                        pass
                    else:
                        continue
                hdpl[head[0]] = value
        except Exception as e:
            print("Oops! prepare data  Internal Error expection:" +  repr(e))
            raise ValueError
        return safepath, hdpl, queryparam

    # Called on GET requests. Return ERROR_CODE, HEADERS, EXTRA
    def on_GET(self, path, headers):
        code = 200
        rheaders = []
        cachehdrs = []
        data = None
        cache_found = False
        try:
            safepath, hdpl, params = self.prepareData(path,headers)
            if safepath:
                print('actualpath:'+ safepath )
            if params:
                print('actualparam:'+ str(params) )
            if hdpl:
                print('actualheaders:'+ str(hdpl) )

            npath = urllib.parse.urlsplit(path).path
            print('npath:' + npath)
            if self._mc:
                cachedata = self._memcache.get("gdata_" + npath)
                cachecode = self._memcache.get("gcode_" + npath)
                cacherheader = self._memcache.get("gheaders_" + npath)
                if cachedata and cacherheader and cachecode:
                    code = cachecode
                    data = cachedata
                    rheaders = cacherheader
                    cache_found = True
                    print('find %s by cache' %(safepath))
                    
            if not cache_found:
                rr = requests.get(safepath, params=params, headers = hdpl)
                rr.encoding = 'utf-8'
                data = rr.text
                code = rr.status_code
                for k,v in rr.headers.items():
                    if k in ('Content-Length', 'Date' ,'Server'):
                        continue
                    rheaders.append((k,v))
                    if not k == 'Cookie':
                        cachehdrs.append((k,v))
                if self._mc:
                    self._memcache.set("gdata_" + npath, data)
                    self._memcache.set("gcode_" + npath, code)
                    self._memcache.set("gheaders_" + npath, cachehdrs)
        except Exception as e:
            print("Oops! on Get Internal Error expection:" + repr(e)) 
            

        #for k,v in rr.headers:
        #    rheaders.append((k,v))
        if code != 200 :
            return code, rheaders, self.responses()[code]
        else:
            return 200, rheaders, data
        #print ("on_Get:" + headers)

        #if path == "/":
        #    return 426, [], "admin@example.com"
        #    # return 500, [], "Basic realm=\"test\""
        #else:
        #    return 200, [], "<html><head><title>My Website</title></head><body>Hi</body></html>"

    def on_POST(self, path, headers, post_data):
        code = 200
        rheaders = []
        cachehdrs = []
        data = None
        cache_found = False
        sep = None
        form_data = False
        post_dict = {}
        file_name='upload.'
        findreqid = False
        try:
            for header in headers:
                if header[0] == 'Lgtpxy_UUID':
                    file_name += header[1] 
                    findreqid = True
                if header[0] == "Content-Type" and 'multipart/form-data' in header[1]:
                    form_data = True
                    options = header[1].split(";")
                    for option in options:
                        if option.strip().startswith("boundary="):
                            sep = "\r\n--" + option.split("=")[1].strip()

            print("post:=" + str(post_data))
            if form_data :
                file_data = None
                post_data = encode.encode_plain("\r\n") + post_data

                if sep is not None:
                    last_sep = sep + "--"
                    # Get the last sep
                    before_end = post_data.split(encode.encode_plain(last_sep))
                    split_form = before_end[0].split(encode.encode_plain(sep))
                    for chunk in split_form:
                        if encode.encode_plain("filename=") in chunk:
                            filechunks = chunk.split(encode.encode_plain("\r\n\r\n"), 1)
                        
                        # Get the name of the file uploaded
                            for metadata in filechunks[0].split(encode.encode_plain("\r\n")):
                                if encode.encode_plain("form-data") in metadata and \
                                    encode.encode_plain("filename=") in metadata:
                                    form_data = metadata.split(encode.encode_plain(";"))
                                    filepara = None
                                    fileval = None
                                    for form_item in form_data:
                                        if encode.encode_plain("name=") in form_item and not encode.encode_plain("filename=") in form_item:
                                            filepara = form_item.split(encode.encode_plain("="), 1)[1][1:-1]
                                        if encode.encode_plain("filename=") in form_item:
                                            formfn = form_item.split(encode.encode_plain("="), 1)[1][1:-1]
                                            fileval = formfn
                                            # Do some basic filtering for uploaded filenames
                                            file_name += "." + encode.decode_plain(formfn).replace(".", "").replace("\\", '')
                                    post_dict[filepara] = fileval
                                    file_data = filechunks[1]
                        else:
                            formparam = chunk.split(encode.encode_plain("\r\n\r\n"), 1)
                            if encode.encode_plain("form-data") in formparam[0] and \
                                encode.encode_plain("name=") in formparam[0]:
                                paramvalue = formparam[1]
                                form_data = formparam[0].split(encode.encode_plain(";"))
                                for form_item in form_data:
                                    if encode.encode_plain("name=") in form_item:
                                        formfn = form_item.split(encode.encode_plain("="), 1)[1][1:-1]
                                        post_dict[formfn] = paramvalue
                            else:
                                print(formparam[0])
                else:
                    file_data = post_data
                if not os.path.exists(file_name):
                    open("./" + file_name, "wb+").write(file_data)
            else:
                post_dict.update(urllib.parse.parse_qs(post_data))
            print(post_dict)
            safepath, hdpl, params = self.prepareData(path,headers)
            npath = urllib.parse.urlsplit(path).path
            if self._mc:
                cachedata = self._memcache.get("pdata_" + npath)
                cachecode = self._memcache.get("pcode_" + npath)
                cacherheader = self._memcache.get("pheaders_" + npath)
                if cachedata and cacherheader and cachecode:
                    code = cachecode
                    data = cachedata
                    rheaders = cacherheader
                    cache_found = True
                    print('find %s by cache' %(safepath))
            if not cache_found:
                rr = requests.post(safepath, params=params, data=post_dict, headers = hdpl)
                data = rr.text
                code = rr.status_code
                for k, v in rr.headers.items():
                    if k in ('Content-Length', 'Date' ,'Server'):
                        continue
                    rheaders.append((k,v))
                    if not k == 'Cookie':
                        cachehdrs.append((k,v))
                if self._mc:
                    self._memcache.set("pdata_" + npath, data)
                    self._memcache.set("pcode_" + npath, code)
                    self._memcache.set("pheaders_" + npath, cachehdrs)
                if not findreqid:
                    print('take care of this post request ' + path)
        except Exception as e:
            print("Oops! Internal Error expection:" + e) 
            

        #for k,v in rr.headers:
        #    rheaders.append((k,v))
        if code != 200 :
            return code, rheaders, self.responses()[code]
        else:
            return 200, rheaders, data
 
    def on_error(self, code, headers, message):
        return code, [("Connection", "close"), ("Content-Type", "text/html; charset=iso-8859-1")], message

    def on_complete(self, client, code, req_headers, res_headers, request, response):
        #print('req:' + str(request))
        self.log(client, request, response, extra={})
        #print('res:' + str(response))
        #self.log(client,request, response)
        # Do something when the request is done and the response is sent
        pass