import typing
import os

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process

from mitmproxy import (command, ctx, flow, types)

import requests

def get_md_dict(multidict):
    """ Return a dict going from cookie names to cookie values
          - Note that it includes both the cookies sent in the original request and
            the cookies sent by the server """
    return {name: value for name, value in multidict}

def make_http_req(mreq):
    # assumes that you have shell environment variables defined for http[s] proxies and CA path
    # that correspond to your mitmproxy configuration
    # eg:
    # export MITMPROXY_CA_BUNDLE="(absolute_path_to).mitmproxy/mitmproxy-ca-cert.pem"
    headers = get_md_dict(mreq.headers.fields)
    cookies = get_md_dict(mreq.cookies.fields)
    proxies = {
        "http" : "http://127.0.0.1:8080",
        "https" : "http://127.0.0.1:8080",
        }

    requests.request(method=mreq.method,
            url=mreq.url,
            headers=headers,
            data=mreq.content,
            cookies=cookies,
            proxies=proxies,
            verify=os.environ.get("MITMPROXY_CA_BUNDLE"),
            timeout=4)

class RequestFuzzer:

    def replay_flow_with_replacements(
            self,
            flow,
            match,
            replacements
        ):

        with ThreadPoolExecutor(max_workers=10) as executor:
            for replacement in replacements:
                dup = flow.copy()
                dup.request.replace(match, replacement)
                executor.submit(make_http_req, dup.request)
                # note: requests.request seems unresponsive when you call it from the
                # same process (proxy server doesn't respond)
                #  p = Process(target=make_http_req, args=(dup.request,))
                #  make_http_req(dup.request)
                #  p.start()

    @command.command("fuzz.request")
    def fuzz_with_replace(
            self,
            flow: flow.Flow,
            path: types.Path,
            match: str
    ) -> None:

        with open(path) as f:
            p=Process(target=self.replay_flow_with_replacements, args=(flow, match, f.read().splitlines()))
            p.start()
                
            #  self.replay_flow_with_replacements(flow, match, f.read().splitlines())

addons = [
    RequestFuzzer()
]
