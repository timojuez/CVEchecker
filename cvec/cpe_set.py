from cpe.cpeset2_3 import CPESet2_3
from cpe.cpe2_3 import CPE2_3 as CPE


class ConfigurationParserMixin:
    """ A configuration is a logical expression by NIST that defines if a CVE
    matches a set of software """
    
    def matches(self, conf): return any([self._parse(e) for e in conf])

    def _parse(self, e): return self._conjunction(e) if e["operator"] == "AND" \
        else self._disjunction(e)

    def _conjunction(self, l): return all(self._resolve(l))

    def _disjunction(self, l): return any(self._resolve(l))

    def _resolve(self, e):
        assert(not ("children" in e and "cpe_match" in e))
        if "children" in e: return [self._parse(f) for f in e["children"]]
        if "cpe_match" in e:
            r = []
            for cpe_dict in e["cpe_match"]:
                cpe = CPE(cpe_dict["cpe23Uri"])
                r.append(self.name_match(cpe))
            return r


class CastableMixin:
    """ CPESet that allows setting elements on init """

    def __init__(self, l=None):
        super().__init__()
        for e in l or []: self.append(e)
        

class CPESet(CastableMixin, ConfigurationParserMixin, CPESet2_3): pass


def load_cpe_file(path):
    """ loads a list of CPEs from a file and returns a CPESet """
    cpe_set = CPESet()
    with open(path) as fp:
        for l in fp:
            l = l.strip()
            if not l or l.startswith("#"): continue
            try: cpe_set.append(CPE(l))
            except:
                print(l)
                raise
    return cpe_set


