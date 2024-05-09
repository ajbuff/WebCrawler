import json
import os
import datetime

from anytree import RenderTree
from helpers import Trademark_Node, Candidate_Node, CNAME_Node, A_Node, Redirect_Node

from urllib.parse import urlparse

from netUtils import DNSInfo, WHOISInfo, ResponseInfo
from helpers import get_logger, create_directory
from config import REDIRECT_COUNT_MAX

class Dumby:
    def __init__(self, name, domain, messages_queue, start_time):
        self.name = name
        self.domain = domain
        self.messages_queue = messages_queue
        self.start_time = start_time

    def save(self):
        total_time = datetime.datetime.now() - self.start_time
        formatted_time = str(total_time)
        self.messages_queue.put(f"{self.name} : {self.domain} : {formatted_time} : SUCCESS")


class Trademark:
    def __init__(self, name, domain, output_directory, messages_queue):
        self.name = name
        self.domain = domain
        self.dir_path = os.path.join(output_directory, name)
        self.map = {}
        self.messages_queue = messages_queue

        self._get_logger()

        # Tree
        self.root = Trademark_Node(self.name, parent=None)

    # Public
    def process(self, stack):
        candidate = Candidate(
            URI=self.domain,
            trademark=self,
            dir_path=os.path.join(self.dir_path, self.domain),
        )

        stack.append(candidate)

    def save(self):
        dir_path = os.path.join(self.dir_path, self.domain)

        create_directory(dir_path)

        filename = os.path.join(dir_path, "TREE")

        with open(filename, "w", encoding="utf-8") as file:
            for pre, _, node in RenderTree(self.root):
                file.write(f"{pre}{node}\n")

    # Private
    def _get_logger(self):
        self.error_logger = get_logger(self.dir_path, self.domain, f"{self.name}_error")

    def __str__(self):
        return f"TRADEMARK - DOMAIN: {self.domain}"


class Url:
    def __init__(self, URI, redirects=0):
        self.url = ""
        self.cname = ""
        self.scheme = ""
        self.domain = ""
        self.path = ""
        self.referrer = ""
        self.redirects = redirects

        self._parse_URI(URI)

    # Private
    def _parse_URI(self, URI):
        if not urlparse(URI).scheme:
            URI = "https://" + URI

        parsed = urlparse(URI)

        self.domain = parsed.hostname

        self.url = URI
        self.scheme = parsed.scheme
        self.path = parsed.path


class Candidate:
    processed = set()

    def __init__(
        self,
        URI="",
        trademark=None,
        num_redirects=0,
        dir_path="",
        parent=None,
    ):
        self.address = Url(URI)
        self.trademark = trademark

        self.num_redirects = num_redirects

        self.dns = DNSInfo(self.domain)

        self.whois = WHOISInfo(self.domain)

        self.dir_path = dir_path

        # Tree
        self.add_to_tree(parent)

    @property
    def domain(self):
        return self.address.domain

    # Public
    def add_to_tree(self, parent):
        if parent:
            self.node = Redirect_Node(self.address.url, parent=parent)
        else:
            self.node = Candidate_Node(self.address.url, parent=self.trademark.root)

    def process(self, stack):
        self._create_records(stack)

    def save(self):
        create_directory(self.dir_path)

        self._save_dns()
        self._save_whois()

    # Private
    def _create_records(self, stack):
        for record_type, records in self.dns.answered_records.items():
            if record_type == "CNAME":
                CNAME_record_num = 0
                for cname in records:
                    cname_record = CNAME(
                        candidate=self,
                        cname=cname,
                        CNAME_record_num=CNAME_record_num,
                        num_redirects=self.num_redirects + 1,
                        parent=self.node,
                    )

                    CNAME_record_num += 1

                    stack.append(cname_record)

            elif record_type == "A":
                A_record_num = 0
                for ip in records:
                    if (
                        self.address.domain,
                        ip,
                        self.address.path,
                    ) in ResponseInfo.processed:
                        A_Node(f"{ip} | *", parent=self.node)
                        continue

                    A_record = A(
                        candidate=self,
                        address=self.address,
                        ip=ip,
                        record_num=A_record_num,
                        num_redirects=self.num_redirects,
                        parent=self.node,
                    )

                    A_record_num += 1

                    stack.append(A_record)

    # Private methods
    def _save_dns(self):
        domain = self.dns.domain

        try:
            filename = os.path.join(
                self.dir_path,
                f"{str(self.num_redirects)}_{domain}_dns",
            )

            with open(filename, "w") as file:
                json.dump(
                    {
                        "domain": domain,
                        "dns_records": self.dns.records,
                        "dns_error": self.dns.errors,
                    },
                    file,
                    indent=4,
                )
        except Exception as dns_save_error:
            self.trademark.error_logger.error(
                f"DNSError : save_error : {self.trademark.domain} : {dns_save_error}"
            )

    def _save_whois(self):
        from datetime import datetime

        def convert_datetime_to_str(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, list):
                return [convert_datetime_to_str(item) for item in obj]
            raise TypeError(f"Type {type(obj)} not serializable")

        domain = self.whois.domain

        try:
            filename = os.path.join(
                self.dir_path,
                f"{str(self.num_redirects)}_{domain}_whois",
            )

            with open(filename, "w") as file:
                json.dump(
                    {
                        "domain": domain,
                        "whois_info": self.whois.info,
                        "whois_raw": self.whois.raw,
                        "whois_error": self.whois.error,
                    },
                    file,
                    indent=4,
                    default=convert_datetime_to_str,
                )
        except Exception as whois_save_error:
            self.trademark.error_logger.error(
                f"WHOISError : save_error : {self.trademark.domain} : {whois_save_error}"
            )

    def __str__(self):
        return (
            f"CANDIDATE - DOMAIN: {self.domain} : NUM_REDIRECTS: {self.num_redirects}"
        )


class A:
    def __init__(
        self, candidate, address, ip="", num_redirects=0, record_num=0, parent=None
    ):
        self.candidate = candidate
        self.address = address

        self.num_redirects = num_redirects
        self.record_num = record_num

        self.response = ResponseInfo(
            domain=address.domain,
            ip=ip,
            path=address.path,
            referrer=address.referrer,
            error_logger=candidate.trademark.error_logger,
        )

        self.dir_name = f"{self.num_redirects}_ip{self.record_num}"
        self.dir_path = os.path.join(candidate.dir_path, self.dir_name)

        # Tree
        self.node = A_Node(self.response.ip, parent=parent)

    # Public
    def process(self, stack):
        if (
            self.response.location
            and self.num_redirects < REDIRECT_COUNT_MAX
            and self.response.location != self.address.url
        ):
            redirect = Candidate(
                URI=self.response.location,
                trademark=self.candidate.trademark,
                num_redirects=self.num_redirects + 1,
                parent=self.node,
            )

            redirect.address.referrer = self.address.url

            redirect.dir_path = os.path.join(self.dir_path, redirect.address.domain)

            stack.append(redirect)
        else:
            if self.response.location:
                Candidate_Node(f"{self.response.location} | X", parent=self.node)

    def save(self):
        create_directory(self.dir_path)

        self._save_cert()
        self._save_response()

    # Private
    def _save_cert(self):
        try:
            path = self.dir_path

            if self.response.cert_binary:
                filename = os.path.join(path, self.dir_name + "_certificate_raw")

                with open(filename, "wb") as file:
                    file.write(self.response.cert_binary)

            if self.response.cert_PEM:
                filename = os.path.join(path, self.dir_name + "_certificate_PEM")

                with open(filename, "w") as file:
                    file.write(self.response.cert_PEM)

        except Exception as cert_save_error:
            self.candidate.trademark.error_logger.error(
                f"CertError : save_error : {self.candidate.trademark.domain} : {cert_save_error}"
            )

    def _save_response(self):
        try:
            path = self.dir_path
            filename = os.path.join(path, self.dir_name + "_response_report")

            with open(filename, "w") as file:
                json.dump(
                    self.response.generate_response_report(),
                    file,
                    indent=4,
                )

            if self.response.body:
                filename = os.path.join(path, self.dir_name + "_body_html")
                with open(filename, "wb") as file:
                    file.write(self.response.body)

        except Exception as save_response_error:
            self.candidate.trademark.error_logger.error(
                f"ResponseError : save_error : {self.candidate.trademark.domain} : {save_response_error}"
            )

    def __str__(self):
        return f"A - DOMAIN: {self.address.domain} IP: {self.response.ip} : NUM_REDIRECTS: {self.num_redirects}"


class CNAME(Candidate):
    def __init__(
        self, candidate, cname="", num_redirects=0, CNAME_record_num=0, parent=None
    ):
        self.cname = cname
        self.CNAME_record_num = CNAME_record_num
        self.num_redirects = num_redirects

        super().__init__(
            URI=candidate.address.url,
            trademark=candidate.trademark,
            num_redirects=self.num_redirects,
            dir_path=candidate.dir_path,
            parent=parent,
        )

        self.dir_name = f"{self.num_redirects}_CNAME_{self.CNAME_record_num}"
        self._dir_path = os.path.join(candidate.dir_path, self.dir_name)

    @property
    def dir_path(self):
        return self._dir_path

    @dir_path.setter
    def dir_path(self, path):
        self._dir_path = path

    @property
    def domain(self):
        return self.cname

    # Public
    def add_to_tree(self, parent):
        self.node = CNAME_Node(self.cname, parent=parent)

    def process(self, stack):
        super().process(stack)

    def save(self):
        super().save()

    def __str__(self):
        return f"CNAME - DOMAIN: {self.cname} : NUM_REDIRECTS: {self.num_redirects}"
