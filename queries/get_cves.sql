-- :name get_cves :many
SELECT packages.*, cve.*
FROM packages
LEFT JOIN product
ON lower(product.product_name) = lower(packages.product_name)
AND product.product_version = packages.product_version -- TODO
LEFT JOIN cve
ON cve.rowid = product.cve
WHERE (cve_id IS NULL OR cve_id NOT IN :blacklist) 
AND (:fromDate IS NULL or publishedDate >= :fromDate)
ORDER BY lower(product.product_name) ASC, impact_score DESC, lastModifiedDate DESC;

