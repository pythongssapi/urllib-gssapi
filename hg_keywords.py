import re

keyword_rx = re.compile('^\$(\w+)\:\s+(\W+)\s*\$$')

# returns tuple (key, value)
# returns None if kwstring is not a keyword expansion
def extract_keyvalue(kwstring):
    mo = keyword_rx.match(kwstring)
    if mo is None: return None

    try:
        return mo.group(1,2)
    except IndexError:
        return None


    
def keywords(*kwstrings):
    dict([extract_kwvalue(kws) for kws in kwstrings])
