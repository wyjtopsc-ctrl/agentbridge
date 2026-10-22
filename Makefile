PY ?= python3

.PHONY: ci test protocol fuzz schema release

ci:
	$(PY) tools/ci.py

test:
	@for t in run_tests run_identity_tests run_mcp_tests run_transport_tests run_anchor_tests run_evidence_tests run_evidence_hardening; do \
		PYTHONPATH=src $(PY) tests/$$t.py | tail -1; done

protocol:
	PYTHONPATH=src $(PY) tools/test_pack_vectors.py
	PYTHONPATH=src $(PY) tools/check_vector_rebuild.py
	PYTHONPATH=src $(PY) tools/check_schema_consistency.py

fuzz:
	PYTHONPATH=src $(PY) tools/fuzz_pack.py --iterations 300

schema:
	$(PY) tools/test_schema_validation.py

release:
	$(PY) tools/build_release.py
