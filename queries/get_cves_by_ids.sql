-- :name get_cves_by_ids :many
SELECT *
FROM cve
WHERE cve_id IN :ids
ORDER BY cve_id

