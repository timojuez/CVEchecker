from packaging.version import LegacyVersion as Version
from cpe.cpeset2_3 import CPESet2_3
from cpe.cpe2_3 import CPE2_3 as CPE


class ConfigurationParserMixin:
    """ A configuration is a logical expression by NIST that defines if a CVE
    matches a set of software """
    
    def matches(self, conf): return any([self._parse(e) for e in conf])

    def _parse(self, e): return self._conjunction(e) if e["operator"] == "AND" \
        else self._disjunction(e)

    def _conjunction(self, l):
        for e in self._resolve(l):
            if not e: return False
        return True

    def _disjunction(self, l):
        for e in self._resolve(l):
            if e: return True
        return False

    def _resolve(self, e):
        assert(not ("children" in e and "cpe_match" in e))
        if "children" in e:
            for f in e["children"]: yield self._parse(f)
        if "cpe_match" in e:
            for cpe_dict in e["cpe_match"]:
                try:
                    cpe = CPE(cpe_dict["cpe23Uri"])
                except NotImplementedError as e:
                    cpe = CPE(cpe_dict["cpe23Uri"].replace("?","\\?"))
                
                matches = self.name_match(cpe)
                if not matches: yield False
                
                listed_versions = [cpe_.get_version()[0] for cpe_ in self 
                    if cpe_.get_product()[0] == cpe.get_product()[0]
                    and cpe_.get_vendor()[0] == cpe.get_vendor()[0]]

                yield matches \
                    and ("versionEndIncluding" not in cpe_dict or any([Version(v) <= Version(cpe_dict["versionEndIncluding"]) for v in listed_versions])) \
                    and ("versionStartIncluding" not in cpe_dict or any([Version(v) >= Version(cpe_dict["versionStartIncluding"]) for v in listed_versions])) \
                    and ("versionStartExcluding" not in cpe_dict or any([Version(v) > Version(cpe_dict["versionStartExcluding"]) for v in listed_versions])) \
                    and ("versionEndExcluding" not in cpe_dict or any([Version(v) < Version(cpe_dict["versionEndExcluding"]) for v in listed_versions]))
                    


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


