import dns.resolver
import socket
import ssl
import whois

from http.client import HTTPConnection, HTTPSConnection

from urllib3.util import make_headers

from config import DNS_TIMEOUT, DNS_LIFETIME_TIMEOUT, REQUEST_TIMEOUT


class DNSInfo:
    def __init__(self, domain):
        self._domain = domain
        self._records = {}
        self._answered_records = {}
        self._errors = {}

        self._get_dns_records()

    @property
    def domain(self):
        return self._domain

    @property
    def errors(self):
        return self._errors

    @property
    def records(self):
        return self._records

    @property
    def answered_records(self):
        return self._answered_records

    def _DNS_error(self, dns_error, type=""):
        self._errors.update({type: str(dns_error)})

    def _get_dns_records(self):
        domain = self._domain

        dns_records = {}
        record_types = ["A", "CNAME", "MX", "NS", "SOA", "TXT"]
        answered_dns_records = {}

        resolver = dns.resolver.Resolver()

        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_LIFETIME_TIMEOUT

        for record_type in record_types:
            try:
                answer = resolver.resolve(domain, record_type)
                dns_records[record_type] = [r.to_text() for r in answer]

                if record_type in ["A", "CNAME"]:
                    answered_dns_records[record_type] = dns_records[record_type]
            except dns.resolver.NoAnswer:
                dns_records[record_type] = "ERROR: NO ANSWER"
            except Exception as dns_error:
                if isinstance(
                    dns_error,
                    (
                        # Lets just catch everything that we aren't sure how to handle for now
                        dns.resolver.LifetimeTimeout,
                        dns.resolver.NXDOMAIN,
                        dns.resolver.NoMetaqueries,
                        dns.resolver.NoNameservers,
                        dns.resolver.NoRootSOA,
                        dns.resolver.NotAbsolute,
                        dns.resolver.YXDOMAIN,
                    ),
                ):
                    self._DNS_error(dns_error, "FATAL")
                    break

        for record_type in set(record_types) - set(dns_records):
            dns_records[record_type] = "ERROR: NO RECORD"

        self._answered_records = answered_dns_records
        self._records = dns_records


class WHOISInfo:
    def __init__(self, domain):
        self._domain = domain.rstrip(
            "."
        )  # Remove trailing dot for absolute path CNAME's
        self._info = ""
        self._raw = ""
        self._error = ""

        self._get_whois()

    @property
    def domain(self):
        return self._domain

    @property
    def whois_info(self):
        return self._info

    @property
    def raw(self):
        return self._raw

    @property
    def info(self):
        return self._info

    @property
    def error(self):
        return self._error

    @error.setter
    def error(self, value):
        self._error = value

    @raw.setter
    def raw(self, value):
        self._raw = value

    @info.setter
    def info(self, value):
        self._info = value

    def _whois_error(self, whois_error):
        self._error = str(whois_error)

    def _get_whois(self):
        domain = self._domain

        try:
            self.info = whois.whois(domain)
            self.raw = self.info.text
        except Exception as whois_error:
            self._whois_error(whois_error)


class ResponseInfo:
    processed = set()

    def __init__(self, domain, ip, path, referrer="", error_logger=None):
        self._domain = domain.rstrip(
            "."
        )  # Remove trailing dot for absolute path CNAME's
        self._ip = ip
        self._path = path
        self._referrer = referrer

        key = (domain, ip, path)

        ResponseInfo.processed.add(key)

        # Headers
        self._request_headers = {}
        self._response_headers = {}

        # Cert
        self._cert_binary = ""
        self._cert_PEM = ""

        # Response
        self._body = ""
        self._protocol = ""
        self._status = ""
        self._location = ""
        self._request_headers = ""
        self._response_headers = ""
        self._response = ""

        # Error Buffers
        self._http_error = ""
        self._https_error = ""
        self._SSL_error = ""

        self._error_logger = error_logger

        self._send_request()
        self._check_redirect()

    @property
    def domain(self):
        return self._domain

    @property
    def ip(self):
        return self._ip

    @property
    def path(self):
        return self._path

    @property
    def referrer(self):
        return self._referrer

    @referrer.setter
    def referrer(self, value):
        self._referrer = value

    @property
    def location(self):
        return self._location

    @property
    def body(self):
        return self._body

    @property
    def cert_binary(self):
        return self._cert_binary

    @property
    def cert_PEM(self):
        return self._cert_PEM

    # Public
    def generate_response_report(self):
        return {
            "domain": self._domain,
            "ip": self._ip,
            "path": self._path,
            "referrer": self.referrer,
            "protocol": self._protocol,
            "status": self._status,
            "request_headers": self._request_headers,
            "response_headers": self._response_headers,
            "http_error": self._http_error,
            "https_error": self._https_error,
            "SSL_error": self._SSL_error,
            "cert_binary_collected": bool(self._cert_binary),
            "cert_PEM_collected": bool(self._cert_PEM),
        }

    # Private
    def _set_HTTP_error(self, http_error):
        self._http_error = str(http_error)
        self._error_logger.error(
            f"HTTP error for domain={self.domain} : path={self.path} : ip={self.ip} : error={self._http_error}"
        )

    def _set_HTTPS_error(self, https_error):
        self._https_error = str(https_error)

    def _check_redirect(self):
        if self._status in [301, 302, 303, 307, 308]:
            location = self._response.getheader("location", default="")

            if location.startswith("/"):
                self._location = self.domain + location
            else:
                self._location = location

    def _send_request(self):
        request_headers = make_headers(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )

        request_headers.update({"Host": self.domain})

        request_headers.update({"Upgrade-Insecure-Requests": "1"})

        if self.referrer:
            request_headers.update({"Referer": self.referrer})

        self._request_headers = request_headers

        resources = []

        try:

            def setup_connection(verify_ssl=True):
                raw_socket = socket.create_connection(
                    (self.ip, 443), timeout=REQUEST_TIMEOUT
                )

                resources.append(raw_socket)

                ssl_context = ssl.create_default_context()
                if not verify_ssl:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                ssl_sock = ssl_context.wrap_socket(
                    raw_socket, server_hostname=self.domain
                )
                resources.append(ssl_sock)

                connection = HTTPSConnection(self.domain, 443, timeout=REQUEST_TIMEOUT)
                connection.sock = ssl_sock
                resources.append(connection)

                return connection, ssl_sock

            try:
                connection, ssl_sock = setup_connection()
            except ssl.SSLCertVerificationError as ssl_error:
                self._set_SSL_error(ssl_error)

                connection, ssl_sock = setup_connection(verify_ssl=False)

            connection.request("GET", self.path, headers=request_headers)

            response = connection.getresponse()

            self._parse_cert(ssl_sock)

            self._parse_response(response, "HTTPS")

        except Exception as HTTPS_error:
            self._set_HTTPS_error(HTTPS_error)

            try:
                connection = HTTPConnection(self.ip, 80, timeout=REQUEST_TIMEOUT)

                connection.request("GET", self.path, headers=request_headers)

                response = connection.getresponse()

                self._parse_response(response, "HTTP")

            except Exception as HTTP_error:
                self._set_HTTP_error(HTTP_error)
        finally:
            for resource in resources:
                try:
                    resource.close()
                except Exception as resource_close_error:
                    continue

    def _parse_cert(self, ssl_sock):
        self._cert_binary = ssl_sock.getpeercert(binary_form=True)
        self._cert_PEM = ssl.DER_cert_to_PEM_cert(self._cert_binary)

    def _parse_response(self, response, protocol=""):
        self._body = response.read()
        self._response_headers = dict(response.headers)
        self._status = response.status
        self._protocol = protocol

        # Adding this in for now
        self._response = response

    def _set_SSL_error(self, ssl_error):
        self._SSL_error = str(ssl_error)
