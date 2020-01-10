-- :name get_unmatched :many
WITH product_ AS (
    SELECT DISTINCT product_name
    FROM product
)
SELECT packages.*
FROM packages
LEFT JOIN product_
ON lower(product_.product_name) = lower(packages.product_name)
WHERE product_.product_name IS NULL
ORDER BY lower(product_.product_name) ASC;

