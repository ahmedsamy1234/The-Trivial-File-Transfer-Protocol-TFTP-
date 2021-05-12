
import sys
import os
import enum
import socket
import _thread


cache = list()


class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,  # NOTHING TO BE DONE HERE ############
                 requested_port: int,
                 requested_path: str,
                 headers: list, version="HTTP/1.0"):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.version = version

        # Headers will be represented as a list of tuples
        # for example ("Host", "www.google.com")
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ("Host", "www.google.com") note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

        ########################################################################################################################

    def to_http_string(self):   # NOTHING TO BE DONE HERE ############

        allheaders = ""
        code = self.method+" "+self.requested_path+" "+self.version+"\r\n"
        x = 0
        for x in range(len(self.headers)):
            allheaders += self.headers[x][0] + ": "+self.headers[x][1]+"\r\n"
        allheaders += "\r\n"
        code += allheaders

        return code

        ########################################################################################################################

    def to_byte_array(self, http_string):   # NOTHING TO BE DONE HERE ############
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

        ########################################################################################################################

    def display(self):  # NOTHING TO BE DONE HERE ############
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))

        ########################################################################################################################


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message, version):  # NOTHING TO BE DONE HERE ############
        self.code = code
        self.message = message
        self.version = version

    def to_http_string(self):  # TO BE FINISHED ################3
        """ Same as above """
        version = self.version
        response = version + " " + str(self.code) + " " + str(self.message) + "\r\n\r\n"
        return response

    def to_byte_array(self, http_string):   # NOTHING TO BE DONE HERE ############
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):  # NOTHING TO BE DONE HERE ############
        print(self.to_http_string())

        ########################################################################################################################


class HttpRequestState(enum.Enum):  # COULD ADD ERROR CODES LIKE 400,...ETC ############
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1

    ########################################################################################################################


def entry_point(proxy_port_number):  # TO BE FINISHED ############

    s = setup_sockets(proxy_port_number)

    while True:

        client, adress = s.accept()
        print(f"Connection established with {adress}")
        msg = client.recv(1024)
        print("received request from client >> ", msg)

        clientRequest = msg.decode("utf-8")
        print("request after decoding >> ", clientRequest)
        _thread.start_new_thread(http_request_pipeline, (adress, clientRequest, client))

    ########################################################################################################################


def setup_sockets(proxy_port_number):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", proxy_port_number))
    s.listen(15)  # this proxy serves up to 15 clients concurrently
    return s

    ########################################################################################################################


def get_version(code):
    parsedBySpace = code.split(" ")
    version = parsedBySpace[2].split("\r\n")[0]
    return version
    ##################################################################################################


# this function is the driver of the received request ############
def http_request_pipeline(adress, clientRequest, client):

    FoundInCache = 0
    global cache
    if(check_http_request_validity(clientRequest) == HttpRequestState.GOOD):        # first check the condition of the request
        # if it was good to go then we parse then sanitize
        request = parse_http_request(adress, clientRequest)
        # if it wasnt then we send the appropriate error message to client
        print("request after parsing >> ")
        request.display()

        request = sanitize_http_request(request)
        print("request after sanitizing >> ")
        request.display()

        iteration = 0
        FoundInCache = 0

        for iteration in range(len(cache)):     # checking the cache if it has an instance of the request
            if(cache[iteration][0] == request.to_http_string()):
                FoundInCache = 1
                break
        if (FoundInCache == 0):     # if the request wasnt found then we establish connection with the server and prepare the request to be sent
            allBytesInRequest = bytearray()
            newsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            newsocket.connect((request.requested_host, request.requested_port))
            # converting the message into bytes to be sent
            y = request.to_byte_array(request.to_http_string())
            newsocket.send(y)
            while True:
                reply = newsocket.recv(12000)
                if (len(reply) > 0):
                    allBytesInRequest += reply
                    client.send(reply)
                if (len(reply) <= 0):       # caching the new reply
                    content = [request.to_http_string(), allBytesInRequest]
                    cache.append(content)
                    break
            newsocket.close()   # disconnect from both client and server
            client.shutdown(socket.SHUT_WR)
            client.close()

        else:       # if we found the request in cache send back the reply
            for iteration in range(len(cache)):
                if(cache[iteration][0] == request.to_http_string()):
                    print("reply sent from cache")
                    client.send(cache[iteration][1])
                    FoundInCache = 0
                    break

            client.close()

    elif (check_http_request_validity(clientRequest) == HttpRequestState.NOT_SUPPORTED):
        error_code = "501"
        error_message = "Not Implemented"
        error_to_send = HttpErrorResponse(error_code, error_message, get_version(clientRequest))
        print("request error : not Implemented")
        client.send(error_to_send.to_byte_array(error_to_send.to_http_string()))
        client.close()
    elif (check_http_request_validity(clientRequest) == HttpRequestState.INVALID_INPUT):
        error_code = "400"
        error_message = "Bad Request"
        error_to_send = HttpErrorResponse(error_code, error_message, get_version(clientRequest))
        client.send(error_to_send.to_byte_array(error_to_send.to_http_string()))
        print(error_to_send.to_http_string())
        print("request error  : it is in invalid")
        client.close()

    ########################################################################################################################


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:  # NOTHING TO BE DONE HERE ############
    i = 1

    method = ""
    version = ""
    headers = []
    host = ""

    port = ""
    original_path = ""
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.
    it does NOT validate the HTTP request.
    """
    # first general test to determine absolute or relative !!
    # "GET / HTTP/1.0\r\nHost: www.google.edu\r\n\r\n"
    test = http_raw_data.split(" ")
    method = test[0]
    #print("general test >> ", test)
    if test[1] == '/':
        # print("relative")
        # "GET / HTTP/1.0      ,     Host: www.google.edu  , Host: www.google.edu ,       \r\n"
        test = http_raw_data.split("\r\n")
        original_path = "/"
        parsed = test[0].split('/ ')                        # "GET / HTTP/1.0
        # version = parsed[1].strip()                         # HTTP/1.0
        while i < len(test):
            if (test[i] != "\r\n" and test[i] != ""):
                tuple = test[i].split(": ")  # Host  , www.google.edu\r\n
                if (i == 1):
                    if (tuple[1].find(":") == -1):
                        port = 80
                    else:
                        port = tuple[1].split(":")[1]
                host = tuple[1]
                tuple_t = [str(tuple[0]), str(tuple[1])]
                headers.append(tuple_t)
            i += 1
    else:              # "GOAT http://www.google.edu/ HTTP/1.0\r\n\r\n"
        # print("absolute")
        # "GOAT , http://www.google.edu/f.html , HTTP/1.0\r\n header \r\n"
        test = http_raw_data.split(" ")
        host_p = test[1].split("http://")  # www.google.edu/f.html
        if (host_p[1].find("/") == -1):
            original_path = "/"
            host = host_p[1]
        else:

            host = host_p[1].split("/")[0]

            original_path = host_p[1]  # host_p[1].split(host_slash)[1]
        method = test[0]
        version = test[2].split("\r\n")[0]
        # HTTP/1.0 , header , \r\n
        headers = makeHeaders(http_raw_data)
        if(host.find(":") != -1):
            port = host.split(":")[1]
        else:
            port = 80
    ret = HttpRequestInfo(source_addr, method, host, port, original_path, headers, version)
    return ret

    ########################################################################################################################


def makeHeaders(code):  # Header factory ############
    headers = []

    parsedHeaders = code.split("\r\n")
    parsedHeaders = parsedHeaders[1:]
    for x in parsedHeaders:
        if x == '':
            parsedHeaders.remove(x)
    for x in parsedHeaders:
        if x == '':
            parsedHeaders.remove(x)
    for eachHeader in parsedHeaders:
        parsingforTuple = eachHeader.split(": ")
        tuple = [parsingforTuple[0], parsingforTuple[1]]
        headers.append(tuple)
    return headers

    ########################################################################################################################


def check_http_request_validity(code) -> HttpRequestState:  # NOTHING TO BE DONE HERE ############
    """
    Checks if an HTTP response is valid
    returns:
    One of values in HttpRequestState
    """
    pathflag = 0
    checkColon = CheckColon(code)
    if (checkColon != 1):
        return HttpRequestState.INVALID_INPUT
    parsedBySpace = code.split(" ")
    method = parsedBySpace[0]
    path = parsedBySpace[1]
    version = parsedBySpace[2].split("\r\n")[0]
    if (version != "HTTP/1.0" and version != "HTTP/1.1"):
        return HttpRequestState.INVALID_INPUT
    if(path[0] == "/" or path[0] == 'h'or path[0] == 'H' or path == 'w'):
        pathflag = 1
    if (pathflag != 1):
        return HttpRequestState.INVALID_INPUT
    flagRelativeOrAbs = checkabolute_or_relative(code)
    if (flagRelativeOrAbs != 1):
        return HttpRequestState.INVALID_INPUT
    NotImplementedmethods = list()
    if (method == "GET"):
        return HttpRequestState.GOOD
    NotImplementedmethods = biuld_up_not_Implemented_cases()
    for x in NotImplementedmethods:
        if (method == x):
            return HttpRequestState.NOT_SUPPORTED
    return HttpRequestState.INVALID_INPUT
    return HttpRequestState.PLACEHOLDER

    ########################################################################################################################


def CheckColon(code):   # NOTHING TO BE DONE HERE ############
    header = code.split("\r\n")[1]
    if (header == ""):
        return 1
    if (header.find(":") == -1):
        return 0
    else:
        return 1

    ########################################################################################################################


# NOTHING TO BE DONE HERE NEEDS TESTING ############
def sanitize_http_request(request_info):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object          # "GOAT http://www.google.edu/f/r/ree HTTP/1.0\r\n\r\n"
    """
    flag = 0
    # first check relative or absolute
    if(request_info.requested_path != "/"):                         # means absolute        www.google.edu/f/r/ree
        host = request_info.requested_host
        host_slash = host + "/"
        request_info.requested_path = "/" + request_info.requested_path.split(host_slash)[1]
        for iteration in range(len(request_info.headers)):
            if (request_info.headers[iteration][0] == "Host"):
                flag = 1
        if (flag == 0):
            tuple = ["Host", host]
            request_info.headers.insert(0, tuple)
        return HttpRequestInfo(request_info.client_address_info, request_info.method, request_info.requested_host, request_info.requested_port, request_info.requested_path, request_info.headers, request_info.version)
    else:
        return request_info

#######################################
# Leave the code below as is.
#######################################


# check if the request was in absolute or relative format ############
def checkabolute_or_relative(code):
    string = ""

    parsedBySpace = code.split(" ")
    if (parsedBySpace[1][0] == "/"):
        string = "relative"
    else:
        string = "abs"
    if (string == "relative"):
        parsedByslash = code.split("\r\n")[1]
        if (parsedByslash == ""):
            #print("no header")
            return 0
        parsebydot = parsedByslash.split(":")
        if(parsebydot[0] == "Host" or parsebydot[0] == "host"):
            return 1
        else:
            #print("relative with no host ")
            return 0
    if (string == "abs"):
        return 1

        ########################################################################################################################


def get_arg(param_index, default=None):  # NOTHING TO BE DONE HERE ############
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.

        ########################################################################################################################


def biuld_up_not_Implemented_cases():
    NotImplementedmethods = list()
    NotImplementedmethods.insert(0, "HEAD")
    NotImplementedmethods.insert(1, "POST")
    NotImplementedmethods.insert(2, "DELETE")
    NotImplementedmethods.insert(3, "CONNECT")
    NotImplementedmethods.insert(4, "PATCH")
    NotImplementedmethods.insert(5, "TRACE")
    NotImplementedmethods.insert(6, "OPTIONS")
    NotImplementedmethods.insert(7, "PUT")
    return NotImplementedmethods


def check_file_name():  # NOTHING TO BE DONE HERE ############
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){2}lab2\.py", script_name)

    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print("file name is good")

        ########################################################################################################################


def main():

    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)
    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
