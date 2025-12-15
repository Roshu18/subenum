
import re

class TakeoverDetector:
    def __init__(self):
        # Format: 'Service Name': {'cname': ['pattern'], 'fingerprint': ['response body pattern']}
        self.signatures = {
            "AWS S3": {
                "cname": [r"s3.amazonaws.com", r"s3-website"],
                "fingerprint": [r"The specified bucket does not exist"]
            },
            "GitHub Pages": {
                "cname": [r"github.io"],
                "fingerprint": [r"There isn't a GitHub Pages site here", r"For root URLs (like http://example.com/) you must provide an index.html file"]
            },
            "Heroku": {
                "cname": [r"herokuapp.com"],
                "fingerprint": [r"Heroku | No such app", r"<title>No such app</title>"]
            },
            "Microsoft Azure": {
                "cname": [r"azurewebsites.net", r"cloudapp.net", r"core.windows.net"],
                "fingerprint": [r"404 Web Site not found"]
            },
            "Bitbucket": {
                "cname": [r"bitbucket.io"],
                "fingerprint": [r"Repository not found"]
            },
            "Shopify": {
                "cname": [r"myshopify.com"],
                "fingerprint": [r"Sorry, this shop is currently unavailable"]
            },
            "Zendesk": {
                "cname": [r"zendesk.com"],
                "fingerprint": [r"Help Center Closed"]
            },
            "Fastly": {
                "cname": [r"fastly.net"],
                "fingerprint": [r"Fastly error: unknown domain"]
            },
             "Pantheon": {
                "cname": [r"pantheonsite.io"],
                "fingerprint": [r"The gods are wise, but do not know of the site which you seek"]
            },
            "Tumblr": {
                 "cname": [r"domains.tumblr.com"],
                "fingerprint": [r"Whatever you were looking for doesn't currently exist at this address"]
            },
            "WordPress": {
                "cname": [r"wordpress.com"],
                "fingerprint": [r"Do you want to register *.wordpress.com?"]
            }
        }

    def check(self, cname: str, response_body: str) -> str:
        """
        Checks for takeover vulnerability.
        Returns 'Service Name' if vulnerable, else None.
        """
        if not cname:
            return None
        
        cname = cname.lower()
        
        for service, sigs in self.signatures.items():
            # 1. Check CNAME match First
            cname_match = False
            for c_pat in sigs['cname']:
                if c_pat in cname:
                    cname_match = True
                    break
            
            if not cname_match:
                continue
                
            # 2. If CNAME matches, check Response Body for fingerprint
            if response_body:
                for f_pat in sigs['fingerprint']:
                    if re.search(f_pat, response_body):
                        return service
                        
        return None
