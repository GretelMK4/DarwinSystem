"""
Shared HTTP handler base for the Darwin servers.

Python's built-in http.server announces itself in several small ways that a
careful visitor can spot (the red-team agents did): it answers in HTTP/1.0,
appends its own version to the Server header (leaving a trailing space when
that is blanked), and uses a distinctive error page. This base class removes
those tells. It does not make a Darwin server indistinguishable from the
product named in its Server header; a determined fingerprinter will still
find differences. In a real deployment, put Darwin behind your normal web
server or proxy so that visitors only ever see that server's behaviour.
"""
from http.server import BaseHTTPRequestHandler


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""
    timeout = 30                         # drop idle keep-alive connections
    error_content_type = "text/html"
    error_message_format = ("<html>\r\n<head><title>%(code)d %(message)s</title></head>\r\n<body>\r\n"
                            "<center><h1>%(code)d %(message)s</h1></center>\r\n</body>\r\n</html>\r\n")

    def version_string(self):
        return self.server_version       # exactly the configured header, nothing appended

    def log_message(self, *args):
        pass                             # the servers keep their own logs

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError):
            self.close_connection = True # the visitor hung up mid-reply: routine, not an error
