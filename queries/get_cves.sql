-- :name get_cves :many
SELECT packages.*, cve.*
FROM packages
LEFT JOIN product
ON product.product_name = packages.product_name
AND product.product_version = packages.product_version -- TODO
LEFT JOIN cve
ON cve.rowid = product.cve
ORDER BY impact_score DESC;

