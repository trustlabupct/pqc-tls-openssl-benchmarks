"""Algorithm registry and metadata definitions."""

import re
from dataclasses import dataclass
from enum import Enum


class AlgorithmType(str, Enum):
    """Type of cryptographic algorithm."""

    KEM = "kem"
    SIGNATURE = "signature"


def normalize_algorithm_name(name: str) -> str:
    """Normalize algorithm name to canonical form.

    Converts various formats to lowercase without separators:
    - ML-KEM-768 -> mlkem768
    - ML-DSA-65 -> mldsa65
    - SPHINCS+-SHA2-128f-simple -> sphincssha2128fsimple
    - Falcon-512 -> falcon512

    Args:
        name: Algorithm name in any format

    Returns:
        Normalized algorithm name (lowercase, no separators)
    """
    normalized = name.lower()

    # Remove common separators (-, _, spaces)
    normalized = re.sub(r"[-_\s]+", "", normalized)

    # Remove the plus sign from SPHINCS+ names.
    normalized = normalized.replace("+", "")

    return normalized


@dataclass(frozen=True)
class Algorithm:
    """Represents a cryptographic algorithm available for benchmarking.

    Attributes:
        name: OQS-provider algorithm identifier. This MUST match exactly
            what oqs-provider/OpenSSL expects for the `openssl speed`
            command. For example: 'mlkem768', 'mldsa65', 'X25519MLKEM768'.
            The casing matters for some hybrid algorithms.
        display_name: Human-readable name (e.g., 'ML-KEM-768')
        type: Algorithm category ('kem' or 'signature')
        security_level: NIST security level (1, 2, 3, or 5)
        variant: Algorithm variant (e.g., 'aes', 'shake')
        is_hybrid: Whether algorithm combines classical + PQC
        is_experimental: Whether algorithm is experimental
        classical_component: Classical algorithm in hybrid (e.g., 'x25519')
        aliases: Alternative names for this algorithm (for user convenience).
            Users can specify any alias and it will resolve to the canonical name.
    """

    name: str
    display_name: str
    type: AlgorithmType
    security_level: int | None = None
    variant: str | None = None
    is_hybrid: bool = False
    is_experimental: bool = False
    classical_component: str | None = None
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate algorithm constraints."""
        if self.is_hybrid and not self.classical_component:
            raise ValueError(
                f"Hybrid algorithm '{self.name}' requires classical_component to be set"
            )
        if self.security_level is not None and self.security_level not in (1, 2, 3, 5):
            raise ValueError(
                f"Invalid security level {self.security_level} for '{self.name}'. "
                "Expected 1, 2, 3, or 5."
            )


class RegistryError(Exception):
    """Raised when there's a conflict in the algorithm registry."""

    pass


class AlgorithmRegistry:
    """Registry of all available algorithms for benchmarking."""

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._algorithms: dict[str, Algorithm] = {}
        self._aliases: dict[str, str] = {}  # alias (lowercase) -> canonical name
        self._normalized: dict[str, str] = {}  # normalized name -> canonical name
        self._lowercase_canonical: dict[str, str] = {}  # lowercase canonical -> canonical name

    def register(self, algorithm: Algorithm, overwrite: bool = False) -> None:
        """Register an algorithm in the registry.

        Also registers any aliases defined for the algorithm,
        and the normalized form of the canonical name.

        Args:
            algorithm: The algorithm to register
            overwrite: If True, allow overwriting existing registrations.
                       If False (default), raise RegistryError on conflicts.

        Raises:
            RegistryError: If algorithm name or alias conflicts with existing registration
                          and overwrite=False.
        """
        # Check for duplicate canonical name
        if algorithm.name in self._algorithms and not overwrite:
            raise RegistryError(
                f"Duplicate algorithm registration: '{algorithm.name}' is already registered. "
                f"Use overwrite=True to replace."
            )

        # Check for canonical name collision via lowercase
        existing_canonical = self._lowercase_canonical.get(algorithm.name.lower())
        if existing_canonical and existing_canonical != algorithm.name and not overwrite:
            raise RegistryError(
                f"Case-insensitive canonical name collision: '{algorithm.name}' conflicts "
                f"with existing '{existing_canonical}'. Names must be unique case-insensitively."
            )

        # Check for alias collisions before registering anything
        for alias in algorithm.aliases:
            alias_lower = alias.lower()
            existing = self._aliases.get(alias_lower)
            if existing and existing != algorithm.name and not overwrite:
                raise RegistryError(
                    f"Alias collision: '{alias}' for '{algorithm.name}' is already mapped to "
                    f"'{existing}'. Each alias must map to exactly one canonical name."
                )
            # Also check if alias collides with existing canonical name
            existing_canonical = self._lowercase_canonical.get(alias_lower)
            if existing_canonical and existing_canonical != algorithm.name and not overwrite:
                raise RegistryError(
                    f"Alias collision: '{alias}' for '{algorithm.name}' conflicts with "
                    f"existing canonical name '{existing_canonical}'."
                )

        # Register the algorithm after all checks pass.
        self._algorithms[algorithm.name] = algorithm
        self._lowercase_canonical[algorithm.name.lower()] = algorithm.name

        # Register normalized form of canonical name
        self._normalized[normalize_algorithm_name(algorithm.name)] = algorithm.name

        # Register aliases
        for alias in algorithm.aliases:
            self._aliases[alias.lower()] = algorithm.name
            # Also register normalized form of alias
            self._normalized[normalize_algorithm_name(alias)] = algorithm.name

    def get(self, name: str) -> Algorithm | None:
        """Get an algorithm by name, alias, or normalized name.

        Lookup order:
        1. Exact canonical name match
        2. Case-insensitive canonical name match (O(1) via lowercase dict)
        3. Exact alias match (case-insensitive)
        4. Normalized name match (strips separators, lowercases)

        Args:
            name: Algorithm name in any format (e.g., "mlkem768", "ML-KEM-768")

        Returns:
            Algorithm if found, None otherwise
        """
        # 1. Direct lookup first (exact canonical name)
        if name in self._algorithms:
            return self._algorithms[name]

        # 2. Case-insensitive canonical name lookup (O(1))
        canonical = self._lowercase_canonical.get(name.lower())
        if canonical:
            return self._algorithms.get(canonical)

        # 3. Try alias lookup (case-insensitive)
        canonical = self._aliases.get(name.lower())
        if canonical:
            return self._algorithms.get(canonical)

        # 4. Try normalized name lookup
        normalized = normalize_algorithm_name(name)
        canonical = self._normalized.get(normalized)
        if canonical:
            return self._algorithms.get(canonical)

        return None

    def get_all(self) -> list[Algorithm]:
        """Get all registered algorithms."""
        return list(self._algorithms.values())

    def get_by_type(self, algo_type: AlgorithmType) -> list[Algorithm]:
        """Get all algorithms of a specific type."""
        return [a for a in self._algorithms.values() if a.type == algo_type]

    def get_hybrids(self) -> list[Algorithm]:
        """Get all hybrid algorithms."""
        return [a for a in self._algorithms.values() if a.is_hybrid]

    def get_pure_pqc(self) -> list[Algorithm]:
        """Get all pure PQC algorithms (non-hybrid)."""
        return [a for a in self._algorithms.values() if not a.is_hybrid]

    def get_experimental(self) -> list[Algorithm]:
        """Get all experimental algorithms."""
        return [a for a in self._algorithms.values() if a.is_experimental]

    def get_non_experimental(self) -> list[Algorithm]:
        """Get all non-experimental algorithms."""
        return [a for a in self._algorithms.values() if not a.is_experimental]


registry = AlgorithmRegistry()
