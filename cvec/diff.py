#!/usr/bin/env python3
import argparse,csv,sys


class Cve(object):
    def __init__(self, o): self._o = o
    
    def __str__(self): return "%s %s"%(self._o.get("cve_id"),self._o)
    
    def __getattr__(self, name): return getattr(self._o,name)
    
    def __getitem__(self, name): return self._o[name]
    
    def __eq__(self, other): return self._o == other._o
    

class CveList(object):

    @classmethod
    def fromfile(self, path):
        with open(path) as fp:
            o = list(csv.DictReader(fp))
            return self(list(map(Cve,o)))
        
    def __init__(self, o): self._o = o
    
    def difference(self, other):
        other_ = [e.get("cve_id") for e in other]
        return CveList([e for e in self._o if e.get("cve_id") not in other_])
    
    def intersection(self, other):
        other_ = [e.get("cve_id") for e in other]
        return CveList(sorted([e for e in self._o if e.get("cve_id") and e.get("cve_id") in other_],key=lambda e:e.get("cve_id")))
        
    def __str__(self): return "\n".join(["\t%s"%e for e in self._o])
    
    def __getattr__(self, name): return getattr(self._o,name)
    
    def __getitem__(self, name): return self._o[name]
    
    def __bool__(self): return bool(self._o)
    
    def __len__(self): return len(self._o)
    

class Report(object):

    def __init__(self,csv_a,csv_b):
        a = CveList.fromfile(csv_a)
        b = CveList.fromfile(csv_b)
        
        show = {
            "New": b.difference(a),
            "Removed": a.difference(b),
            "Changed": self._change(a,b),
        }
        for name, val in show.items():
            print("%s:"%name)
            print(val or "\tnothing")
            print()
            print()
        
    def _change(self, a, b):
        changed = [(x,y) for x,y in zip(a.intersection(b),b.intersection(a)) if x!=y]
        changed = [(x.get("cve_id"),
                [(k,x.get(k),y.get(k)) for k,v in x.items() if y.get(k) != v])
            for x,y in changed]
        return "\n".join(["%s:\n%s"%(cveid,"\n".join(["\t%s: '%s' -> '%s'"%(name,old,new) for name,old,new in v])) for cveid,v in changed])
        

class Main:
    def __init__(self):
        parser = argparse.ArgumentParser(description="")
        parser.add_argument('old_csv', help='')
        parser.add_argument('new_csv', help='')
        self.args = parser.parse_args()
        Report(self.args.old_csv, self.args.new_csv)


if __name__ == '__main__':
    Main()

