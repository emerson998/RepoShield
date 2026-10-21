-- Fixture sintética: revisar projeção, filtro, busca textual e paginação profunda.
SELECT *
FROM orders
WHERE LOWER(customer_email) = 'example.invalid'
  AND description LIKE '%sample%'
ORDER BY id
OFFSET 50000;
