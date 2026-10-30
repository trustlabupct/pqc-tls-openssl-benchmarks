"""Tests for algorithm registry resolution and collision detection."""

import pytest

from pqc_bench.algorithms.registry import (
    Algorithm,
    AlgorithmRegistry,
    AlgorithmType,
    RegistryError,
    normalize_algorithm_name,
)


class TestNormalizeAlgorithmName:
    """Tests for normalize_algorithm_name function."""

    def test_lowercase_passthrough(self):
        """Already lowercase names pass through."""
        assert normalize_algorithm_name("mlkem768") == "mlkem768"

    def test_uppercase_to_lowercase(self):
        """Uppercase names are lowercased."""
        assert normalize_algorithm_name("MLKEM768") == "mlkem768"

    def test_mixed_case(self):
        """Mixed case names are lowercased."""
        assert normalize_algorithm_name("MlKem768") == "mlkem768"

    def test_hyphen_removal(self):
        """Hyphens are removed."""
        assert normalize_algorithm_name("ML-KEM-768") == "mlkem768"
        assert normalize_algorithm_name("ml-kem-768") == "mlkem768"

    def test_underscore_removal(self):
        """Underscores are removed."""
        assert normalize_algorithm_name("ml_kem_768") == "mlkem768"

    def test_space_removal(self):
        """Spaces are removed."""
        assert normalize_algorithm_name("ML KEM 768") == "mlkem768"

    def test_plus_sign_removal(self):
        """Plus signs are removed (SPHINCS+ case)."""
        assert normalize_algorithm_name("SPHINCS+-SHA2-128f") == "sphincssha2128f"

    def test_complex_name(self):
        """Complex names with multiple separators."""
        assert normalize_algorithm_name("SPHINCS+-SHA2-128f-simple") == "sphincssha2128fsimple"

    def test_ml_dsa(self):
        """ML-DSA variants normalize correctly."""
        assert normalize_algorithm_name("ML-DSA-65") == "mldsa65"
        assert normalize_algorithm_name("mldsa65") == "mldsa65"
        assert normalize_algorithm_name("MLDSA65") == "mldsa65"


class TestAlgorithmRegistry:
    """Tests for AlgorithmRegistry class."""

    def test_register_and_get_exact(self):
        """Register and retrieve by exact canonical name."""
        reg = AlgorithmRegistry()
        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
            security_level=3,
        )
        reg.register(algo)

        result = reg.get("mlkem768")
        assert result is not None
        assert result.name == "mlkem768"
        assert result.display_name == "ML-KEM-768"

    def test_get_case_insensitive(self):
        """Retrieve by case-insensitive canonical name."""
        reg = AlgorithmRegistry()
        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
        )
        reg.register(algo)

        assert reg.get("MLKEM768") is not None
        assert reg.get("MlKem768") is not None
        assert reg.get("mlkem768") is not None

    def test_get_by_alias(self):
        """Retrieve by alias."""
        reg = AlgorithmRegistry()
        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
            aliases=("ML-KEM-768", "kyber768"),
        )
        reg.register(algo)

        assert reg.get("ML-KEM-768") is not None
        assert reg.get("kyber768") is not None
        assert reg.get("KYBER768") is not None  # case-insensitive alias

    def test_get_by_normalized_name(self):
        """Retrieve by normalized name (hyphen/underscore removed)."""
        reg = AlgorithmRegistry()
        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
        )
        reg.register(algo)

        # Various formats should all resolve
        assert reg.get("ml-kem-768") is not None
        assert reg.get("ML_KEM_768") is not None
        assert reg.get("ML KEM 768") is not None

    def test_get_nonexistent(self):
        """Non-existent algorithm returns None."""
        reg = AlgorithmRegistry()
        assert reg.get("nonexistent") is None

    def test_get_all(self):
        """Get all registered algorithms."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(name="mlkem768", display_name="ML-KEM-768", type=AlgorithmType.KEM)
        algo2 = Algorithm(name="mldsa65", display_name="ML-DSA-65", type=AlgorithmType.SIGNATURE)
        reg.register(algo1)
        reg.register(algo2)

        all_algos = reg.get_all()
        assert len(all_algos) == 2
        names = {a.name for a in all_algos}
        assert names == {"mlkem768", "mldsa65"}

    def test_get_by_type(self):
        """Get algorithms filtered by type."""
        reg = AlgorithmRegistry()
        kem = Algorithm(name="mlkem768", display_name="ML-KEM-768", type=AlgorithmType.KEM)
        sig = Algorithm(name="mldsa65", display_name="ML-DSA-65", type=AlgorithmType.SIGNATURE)
        reg.register(kem)
        reg.register(sig)

        kems = reg.get_by_type(AlgorithmType.KEM)
        assert len(kems) == 1
        assert kems[0].name == "mlkem768"

        sigs = reg.get_by_type(AlgorithmType.SIGNATURE)
        assert len(sigs) == 1
        assert sigs[0].name == "mldsa65"


class TestRegistryCollisionDetection:
    """Tests for registry collision detection."""

    def test_duplicate_canonical_raises(self):
        """Registering duplicate canonical name raises RegistryError."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(name="mlkem768", display_name="ML-KEM-768", type=AlgorithmType.KEM)
        algo2 = Algorithm(name="mlkem768", display_name="Other", type=AlgorithmType.KEM)

        reg.register(algo1)
        with pytest.raises(RegistryError) as exc_info:
            reg.register(algo2)

        assert "Duplicate algorithm registration" in str(exc_info.value)
        assert "mlkem768" in str(exc_info.value)

    def test_duplicate_canonical_with_overwrite(self):
        """Overwrite=True allows replacing existing registration."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(name="mlkem768", display_name="Original", type=AlgorithmType.KEM)
        algo2 = Algorithm(name="mlkem768", display_name="Replacement", type=AlgorithmType.KEM)

        reg.register(algo1)
        reg.register(algo2, overwrite=True)

        result = reg.get("mlkem768")
        assert result is not None
        assert result.display_name == "Replacement"

    def test_case_insensitive_canonical_collision(self):
        """Case-insensitive canonical name collision raises RegistryError."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(name="mlkem768", display_name="Lowercase", type=AlgorithmType.KEM)
        algo2 = Algorithm(name="MLKEM768", display_name="Uppercase", type=AlgorithmType.KEM)

        reg.register(algo1)
        with pytest.raises(RegistryError) as exc_info:
            reg.register(algo2)

        assert "Case-insensitive canonical name collision" in str(exc_info.value)

    def test_alias_collision_different_canonicals(self):
        """Alias mapping to different canonical raises RegistryError."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
            aliases=("kyber768",),
        )
        algo2 = Algorithm(
            name="kyber768_v2",
            display_name="Kyber-768 v2",
            type=AlgorithmType.KEM,
            aliases=("kyber768",),  # Reuse the alias to test collision handling.
        )

        reg.register(algo1)
        with pytest.raises(RegistryError) as exc_info:
            reg.register(algo2)

        assert "Alias collision" in str(exc_info.value)
        assert "kyber768" in str(exc_info.value)

    def test_alias_collides_with_existing_canonical(self):
        """Alias that conflicts with existing canonical name raises RegistryError."""
        reg = AlgorithmRegistry()
        algo1 = Algorithm(name="mlkem768", display_name="ML-KEM-768", type=AlgorithmType.KEM)
        algo2 = Algorithm(
            name="other_algo",
            display_name="Other",
            type=AlgorithmType.KEM,
            aliases=("mlkem768",),  # Collides with algo1's canonical name
        )

        reg.register(algo1)
        with pytest.raises(RegistryError) as exc_info:
            reg.register(algo2)

        assert "Alias collision" in str(exc_info.value)

    def test_same_algo_same_alias_no_collision(self):
        """Re-registering same algorithm with overwrite=True doesn't raise."""
        reg = AlgorithmRegistry()
        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
            aliases=("kyber768",),
        )

        reg.register(algo)
        # Same algorithm again with overwrite
        reg.register(algo, overwrite=True)

        result = reg.get("mlkem768")
        assert result is not None


class TestAlgorithmValidation:
    """Tests for Algorithm dataclass validation."""

    def test_hybrid_requires_classical_component(self):
        """Hybrid algorithm requires classical_component."""
        with pytest.raises(ValueError) as exc_info:
            Algorithm(
                name="x25519_mlkem768",
                display_name="X25519+ML-KEM-768",
                type=AlgorithmType.KEM,
                is_hybrid=True,
                # Missing classical_component
            )

        assert "classical_component" in str(exc_info.value)

    def test_hybrid_with_classical_component(self):
        """Hybrid algorithm with classical_component is valid."""
        algo = Algorithm(
            name="x25519_mlkem768",
            display_name="X25519+ML-KEM-768",
            type=AlgorithmType.KEM,
            is_hybrid=True,
            classical_component="x25519",
        )
        assert algo.classical_component == "x25519"

    def test_invalid_security_level(self):
        """Invalid security level raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            Algorithm(
                name="test",
                display_name="Test",
                type=AlgorithmType.KEM,
                security_level=4,  # Invalid - must be 1, 2, 3, or 5
            )

        assert "security level" in str(exc_info.value).lower()

    def test_valid_security_levels(self):
        """Valid security levels (1, 2, 3, 5) are accepted."""
        for level in (1, 2, 3, 5):
            algo = Algorithm(
                name=f"test{level}",
                display_name=f"Test L{level}",
                type=AlgorithmType.KEM,
                security_level=level,
            )
            assert algo.security_level == level
