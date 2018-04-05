import sys
reload(sys)
sys.setdefaultencoding('utf8')
import requests
import datetime
#import sys
import ssl
import OpenSSL
import socket
import hashlib
import optparse
import ast

class WebMonitoring:
    __webURL = ""
    __timeout = int(0)
    __header = ""
    __response = ""
    def __init__(self, webURL, timeout = None, header = None):
        self.__webURL = webURL
        if timeout is not None and str(timeout).upper() != "NONE":
            self.__timeout = int(timeout)
        else:
            self.__timeout = int(30)
        if header is not None and str(header).upper() != "NONE":
            self.__header = header
            self.__header = ast.literal_eval(str(self.__header))
        else:
            self.__header = None
        self.__response = requests.get(str(self.__webURL), headers = self.__header, timeout = self.__timeout)

    """
    1. Function Name: urlDiscovery
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
         JSON =
            {
                "data":[
                        [
                                {
                                "{#URL}":"",
                                "{#HEADER}":"",
                                "{#TIMEOUT}":""
                                }
                        ]
                ]
            }
           -1 = ERROR
    4. Function Objective:
            Check if the URL is reachable with the given header and within the time limit.
    """
    def urlDiscovery(self):
        try:
            if(int(self.urlResponseCode()) == 200):
                data = '{{"{{#URL}}":"{URL}", "{{#HEADER}}":"{HEADER}", "{{#TIMEOUT}}":"{TIMEOUT}"}}'.format(URL = str(self.__webURL), HEADER = str(self.__header), TIMEOUT = str(self.__timeout))
                json = '{{"data":[{DATA}]}}'.format(DATA = data)
            return str(json)
        except:
            return -1

    """
    1. Function Name: urlAvailability
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
            1 = URL Available
            0 = URL Unavailable
           -1 = ERROR
    4. Function Objective:
            Check if the URL is reachable with the given header and within the time limit.
    """

    def urlAvailability(self):
        try:
            if(self.__response.status_code == 200):
                return 1
            else:
                return 0
        except:
            return -1

    """
    1. Function Name: urlDownloadSpeed
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
          int = URL Download Speed in Bytes per second
           -1 = ERROR
    4. Function Objective:
            Check if the URL is reachable with the given header and within the time limit.
    """

    def urlDownloadSpeed(self):
        URL = str(self.__webURL)
        startTime=datetime.datetime.now()
        try:
            output=ast.literal_eval(str(self.__header))
            response = requests.get(str(URL), headers = output, timeout = self.__timeout)
        except:
            return -1
        else:
            if(response.status_code == 200):
                endTime = datetime.datetime.now()
                duration = (endTime - startTime)
                total = duration.seconds + duration.microseconds/1E6
                bps = 0
                if total >= 0:
                    bps = len(response.content)/total
                return str("{0:.2f}".format(round((abs(bps)))))
            else:
                return -1

    """
    1. Function Name: urlContentCheck
    2. Function Parameter:
            content = contains the content which needs to be checked with the URL
    3. Fuction Output:
            1 = Content Matched
            0 = Content Doesn't Match
           -1 = ERROR
    4. Function Objective:
            Check if the URL has the required contents with the given header and within the timeout limit.
    """

    def urlContentCheck(self,content):
        try:
            if(self.__response.status_code == 200):
                if self.__response.text:
                    if content:
                        if str(content) in str(self.__response.text):
                            return 1
                        else:
                            return 0
                    else:
                        return 1
                else:
                    return 0
            else:
                return 0
        except:
            return -1

    """
    1. Function Name: urlResponseCode
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
          int = Response Code
           -1 = ERROR
    4. Function Objective:
            Get the Response Code for the given URL with the given header.
    """

    def urlResponseCode(self):
        try:
            return str(self.__response.status_code)
        except:
            return -1

    """
    1. Function Name: urlResponseTime
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
          Int = response time of the url
           -1 = ERROR
    4. Function Objective:
            Get the response time for the given URL with the given header.
    """

    def urlResponseTime(self):
        URL = str(self.__webURL)
        startTime=datetime.datetime.now()
        try:
            output=ast.literal_eval(str(self.__header))
            response = requests.get(str(URL), headers = output, timeout = self.__timeout)
        except:
            return -1
        else:
            if(response.status_code == 200):
                endTime=datetime.datetime.now()
                duration=str("{0:.2f}".format(round((abs((endTime-startTime).microseconds)/1000),2)))
                return str(duration)
            else:
                return -1

    """
    1. Function Name: urlResponseTime
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
          Int = response time of the url
           -1 = ERROR
    4. Function Objective:
            Get the response time for the given URL with the given header.
    """

    def urlChecksum(self):
        try:
            if(self.__response.status_code == 200):
                return str(hashlib.md5(str(self.__response.text)).hexdigest())
            else:
                return -1
        except:
            return -1

    """
    1. Function Name: certificateMonitoring
    2. Function Parameter:
            No Parameter required
    3. Fuction Output:
          Int = Number of days left for certificate to expire
           -1 = ERROR
    4. Function Objective:
            Get the number of days left for certificate to expire for the given URL with the given header.
    """

    def certificateMonitoring(self):
        try:
            URL = str(self.__webURL)
            URL=URL.replace("https://","").replace("http://","")
            ARG=list()
            ARG=URL.split(":")
            if(len(ARG)==1):
                URL=ARG[0]
                PORT=443
            elif(len(ARG)==2):
                URL=ARG[0]
                PORT=ARG[1]
            else:
                return -1
            host=socket.getaddrinfo(URL, PORT)[0][4][0]
            cert=ssl.get_server_certificate((host,443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            startdate=str(x509.get_notAfter().decode("utf-8")).replace("Z","")
            enddate=str((datetime.datetime.now()).strftime("%Y%m%d%H%M%S"))
            d1 = datetime.datetime.strptime(startdate, "%Y%m%d%H%M%S")
            d2 = datetime.datetime.strptime(enddate, "%Y%m%d%H%M%S")
            diff=abs((d1 - d2).days)
            return str(diff)
        except:
            return -1

def main():
    parser = optparse.OptionParser()
    parser.add_option("--metric", help="Specify the required metric to output")
    parser.add_option("--url", help="Specify the URL to be monitored")
    parser.add_option("--header", help="Specify the header of the URL")
    parser.add_option("--timeout", help="Specify (HTTP) Extra header to include in the request when sending HTTP to a server of the URL")
    parser.add_option("--content", help="Specify the content to be checked when using --metric=content-check with the URL")
    (options, args) = parser.parse_args()

    if not options.metric or not options.url:
        parser.error("Atleast one --metric and one --URL should be specified")
        return

    metric = None if not options.metric else options.metric
    url = None if not options.url else options.url
    timeout = None if not options.timeout else options.timeout
    header = None if not options.header else options.header
    content = None if not options.content else options.content

    obj = WebMonitoring(url, timeout, header)

    if(str(metric).lower() == "discovery"):
        print(str(obj.urlDiscovery()))
    elif(str(metric).lower() == "availability"):
        print(str(obj.urlAvailability()))
    elif(str(metric).lower() == "certificate-expiry"):
        print(str(obj.certificateMonitoring()))
    elif(str(metric).lower() == "response-code"):
        print(str(obj.urlResponseCode()))
    elif(str(metric).lower() == "response-time"):
        print(str(obj.urlResponseTime()))
    elif(str(metric).lower() == "checksum"):
        print(str(obj.urlChecksum()))
    elif(str(metric).lower() == "content-check"):
        if not content:
            parser.error('content to be checked should be specified using --content')
        else:
            print(str(obj.urlContentCheck(str(content))))
    elif(str(metric).lower() == "download-speed"):
        print(str(obj.urlDownloadSpeed()))
    else:
        parser.error("Invalid Metric")

if __name__ == "__main__":
    main()
