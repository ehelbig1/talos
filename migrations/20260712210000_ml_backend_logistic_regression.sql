-- RFC 0011 P3 — name the parametric backend by its ALGORITHM.
--
-- The initial P3 cut tagged the backend `classical` (the RFC's family
-- placeholder) because the `backend` CHECK didn't allow anything more
-- specific. But the algorithm is logistic regression, and naming it
-- explicitly is clearer + consistent with `knn-pgvector` being
-- algorithm-specific rather than a family. This widens the CHECK to allow
-- the specific tag and re-tags the interim rows. The vague family tags
-- (`classical`/`statistical`) stay allowed for any future use.
ALTER TABLE ml_model_versions DROP CONSTRAINT IF EXISTS ml_model_versions_backend_check;
ALTER TABLE ml_model_versions
    ADD CONSTRAINT ml_model_versions_backend_check
    CHECK (backend IN (
        'llm', 'knn-pgvector', 'classical', 'statistical', 'onnx', 'logistic-regression'
    ));

-- Re-tag any rows written under the interim `classical` name (order is
-- safe: the CHECK above already permits the new value).
UPDATE ml_model_versions SET backend = 'logistic-regression' WHERE backend = 'classical';
