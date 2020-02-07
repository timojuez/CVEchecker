-- :name get_cves_by_ids
SELECT *
FROM cve
WHERE cve_id IN :ids

