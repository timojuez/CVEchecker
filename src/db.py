import pugsql

cve_db = pugsql.module("queries/")
cve_db.connect("sqlite:///cve_db.db")

