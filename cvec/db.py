import pugsql
from importlib import resources

_generator = resources.path("cvec","queries")
_path = _generator.__enter__()

cve_db = pugsql.module(_path)
cve_db.connect("sqlite:///cve_db.db")

