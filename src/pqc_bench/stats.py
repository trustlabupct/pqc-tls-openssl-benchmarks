"""Statistical calculations for benchmark results."""

import statistics
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class Stats:
    """Statistical summary of timing measurements.

    Attributes:
        median: Median value (50th percentile)
        p95: 95th percentile value
        p99: 99th percentile value
        min: Minimum value
        max: Maximum value
        count: Number of measurements
        mean: Arithmetic mean
        stdev: Standard deviation (None if count < 2)
    """

    median: float
    p95: float
    p99: float
    min: float
    max: float
    count: int
    mean: float
    stdev: float | None = None


def calculate_percentile(sorted_data: Sequence[float], percentile: float) -> float:
    """Calculate a specific percentile from sorted data.

    Uses linear interpolation method.

    Args:
        sorted_data: Pre-sorted sequence of values
        percentile: Percentile to calculate (0-100)

    Returns:
        The calculated percentile value
    """
    if not sorted_data:
        raise ValueError("Cannot calculate percentile of empty sequence")

    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]

    index = (percentile / 100) * (n - 1)
    lower_idx = int(index)
    upper_idx = min(lower_idx + 1, n - 1)
    fraction = index - lower_idx

    # Linear interpolation
    return sorted_data[lower_idx] + fraction * (sorted_data[upper_idx] - sorted_data[lower_idx])


def calculate_stats(timings: Sequence[float]) -> Stats:
    """Calculate statistical summary from timing measurements.

    Computes median, p95, p99, min, max, mean, and standard deviation
    from a sequence of timing values.

    Args:
        timings: Sequence of timing values in microseconds

    Returns:
        Stats object containing all calculated statistics

    Raises:
        ValueError: If timings is empty
    """
    if not timings:
        raise ValueError("Cannot calculate stats from empty timings")

    sorted_timings = sorted(timings)
    n = len(sorted_timings)

    # Standard deviation requires at least two samples.
    stdev = None
    if n >= 2:
        stdev = statistics.stdev(sorted_timings)

    return Stats(
        median=statistics.median(sorted_timings),
        p95=calculate_percentile(sorted_timings, 95),
        p99=calculate_percentile(sorted_timings, 99),
        min=min(sorted_timings),
        max=max(sorted_timings),
        count=n,
        mean=statistics.mean(sorted_timings),
        stdev=stdev,
    )


def ops_per_second(median_us: float) -> float:
    """Calculate operations per second from median latency in microseconds.

    Args:
        median_us: Median latency in microseconds

    Returns:
        Operations per second
    """
    if median_us <= 0:
        raise ValueError("Median latency must be positive")
    return 1_000_000 / median_us
