from mitmproxy import http
from glob import glob
from adblockparser import AdblockRules
from mitmproxy.http import HTTPResponse
from mitmproxy.net.http import Headers
from urllib.parse import urlparse
from mitmproxy.script import concurrent
try:
    import re2 as re
except ImportError:
    import re


IMAGE_MATCHER      = re.compile(r"\.(png|jpe?g|gif)$")
SCRIPT_MATCHER     = re.compile(r"\.(js)$")
STYLESHEET_MATCHER = re.compile(r"\.(css)$")

def combined(filenames):
  '''
  Open and combine many files into a single generator which returns all
  of their lines. (Like running "cat" on a bunch of files.)
  '''
  for filename in filenames:
    with open(filename) as file:
      for line in file:
        yield line

def load_rules(blocklists=None):
    rules = AdblockRules(
        combined(blocklists),
        #use_re2=True,
        max_mem=512*1024*1024,
        supported_options=['script', 'domain', 'image', 'stylesheet', 'object']
    )

    return rules

def find_o_or_r_header(headers):
    h = headers.get_all("origin")
    if len(h) != 1:
        h = headers.get_all("referer")

    if len(h) == 1:
        return h[0]

    return ""

blocklists = glob("blocklists/*")

print("* Loading blocklists...")
rules = load_rules(blocklists)
print("")
print("* Done! Proxy server is ready to go!")

class RequestBlocker:
    def __init__(self):
        self.blocked = 0

    @concurrent
    def request(self, flow):
        global rules

        req = flow.request
        # accept = flow.request.headers["Accept"]
        # log("accept: %s" % flow.request.accept)

        options = {'domain': req.host}
        #print(req.headers)

        if IMAGE_MATCHER.search(req.path):
            options["image"] = True
        elif SCRIPT_MATCHER.search(req.path):
            options["script"] = True
        elif STYLESHEET_MATCHER.search(req.path):
            options["stylesheet"] = True

        third_party = False
        origin_or_referer = find_o_or_r_header(req.headers)

        if origin_or_referer != "":
            host = urlparse(origin_or_referer).hostname
            if host != req.host:
                third_party = True

        if third_party == True:
            options["third-party"] = True

        if rules.should_block(req.url, options):
            print("vvvvvvvvvvvvvvvvvvvv BLOCKED vvvvvvvvvvvvvvvvvvvvvvvvvvv")
            print("accept: %s" % flow.request.headers.get("Accept"))
            print("blocked-url: %s" % flow.request.url)
            if third_party == True:
                print("request-origin: %s" % origin_or_referer)
            print("^^^^^^^^^^^^^^^^^^^^ BLOCKED ^^^^^^^^^^^^^^^^^^^^^^^^^^^")

            flow.response = HTTPResponse.make(
                200,
                "OK",
                {"Content-Type": "text/html"}
            )
        #else:
            #print("url: %s" % flow.request.url)

addons = [
    RequestBlocker()
]
