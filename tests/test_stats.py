"""Tests for the stats module."""

import pytest

from pqc_bench.stats import Stats, calculate_percentile, calculate_stats, ops_per_second


class TestCalculatePercentile:
    """Tests for calculate_percentile function."""

    def test_empty_sequence_raises(self):
        """Empty sequence should raise ValueError."""
        with pytest.raises(ValueError, match="empty sequence"):
            calculate_percentile([], 50)

    def test_singleton_returns_value(self):
        """Single-element sequence returns that element for any percentile."""
        assert calculate_percentile([42.0], 0) == 42.0
        assert calculate_percentile([42.0], 50) == 42.0
        assert calculate_percentile([42.0], 100) == 42.0

    def test_two_elements_interpolation(self):
        """Two elements should interpolate correctly."""
        data = [10.0, 20.0]
        assert calculate_percentile(data, 0) == 10.0
        assert calculate_percentile(data, 50) == 15.0
        assert calculate_percentile(data, 100) == 20.0

    def test_known_p50_odd_count(self):
        """P50 of odd-length sequence is the middle element."""
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert calculate_percentile(data, 50) == 3.0

    def test_known_p50_even_count(self):
        """P50 of even-length sequence interpolates between middle elements."""
        data = [1.0, 2.0, 3.0, 4.0]
        # Index = 0.5 * 3 = 1.5, so interpolate between index 1 and 2
        # = 2.0 + 0.5 * (3.0 - 2.0) = 2.5
        assert calculate_percentile(data, 50) == 2.5

    def test_p95_ten_elements(self):
        """P95 with 10 elements should interpolate correctly."""
        data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        # Index = 0.95 * 9 = 8.55
        # lower_idx = 8, upper_idx = 9, fraction = 0.55
        # = 9.0 + 0.55 * (10.0 - 9.0) = 9.55
        assert calculate_percentile(data, 95) == pytest.approx(9.55)

    def test_p99_hundred_elements(self):
        """P99 with 100 elements."""
        data = [float(i) for i in range(1, 101)]  # 1.0 to 100.0
        # Index = 0.99 * 99 = 98.01
        # lower_idx = 98, upper_idx = 99, fraction = 0.01
        # data[98] = 99.0, data[99] = 100.0
        # = 99.0 + 0.01 * 1.0 = 99.01
        assert calculate_percentile(data, 99) == pytest.approx(99.01)

    def test_p0_is_minimum(self):
        """P0 should return the minimum value."""
        data = [5.0, 10.0, 15.0, 20.0]
        assert calculate_percentile(data, 0) == 5.0

    def test_p100_is_maximum(self):
        """P100 should return the maximum value."""
        data = [5.0, 10.0, 15.0, 20.0]
        assert calculate_percentile(data, 100) == 20.0

    def test_repeated_values(self):
        """Repeated values should be handled correctly."""
        data = [5.0, 5.0, 5.0, 5.0, 5.0]
        assert calculate_percentile(data, 50) == 5.0
        assert calculate_percentile(data, 95) == 5.0


class TestCalculateStats:
    """Tests for calculate_stats function."""

    def test_empty_timings_raises(self):
        """Empty timings should raise ValueError."""
        with pytest.raises(ValueError, match="empty timings"):
            calculate_stats([])

    def test_singleton_no_stdev(self):
        """Single timing has no standard deviation."""
        stats = calculate_stats([100.0])
        assert stats.count == 1
        assert stats.median == 100.0
        assert stats.mean == 100.0
        assert stats.min == 100.0
        assert stats.max == 100.0
        assert stats.stdev is None

    def test_two_elements_has_stdev(self):
        """Two elements should have a standard deviation."""
        stats = calculate_stats([100.0, 200.0])
        assert stats.count == 2
        assert stats.stdev is not None
        assert stats.stdev > 0

    def test_known_statistics(self):
        """Test with known values."""
        # 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
        timings = [float(i) for i in range(1, 11)]
        stats = calculate_stats(timings)

        assert stats.count == 10
        assert stats.min == 1.0
        assert stats.max == 10.0
        assert stats.median == 5.5  # Average of 5 and 6
        assert stats.mean == 5.5
        assert stats.p95 == pytest.approx(9.55)
        assert stats.p99 == pytest.approx(9.91)

    def test_unsorted_input(self):
        """Input does not need to be pre-sorted."""
        timings = [5.0, 1.0, 3.0, 2.0, 4.0]
        stats = calculate_stats(timings)
        assert stats.median == 3.0
        assert stats.min == 1.0
        assert stats.max == 5.0

    def test_repeated_values(self):
        """All same values should have zero stdev."""
        timings = [42.0, 42.0, 42.0, 42.0]
        stats = calculate_stats(timings)
        assert stats.median == 42.0
        assert stats.mean == 42.0
        assert stats.stdev == 0.0

    def test_realistic_benchmark_data(self):
        """Test with realistic-looking benchmark timings."""
        # Simulate 10 samples with some variance
        timings = [
            1234.5,
            1256.2,
            1245.8,
            1238.1,
            1262.4,
            1241.0,
            1250.3,
            1233.7,
            1248.9,
            1255.1,
        ]
        stats = calculate_stats(timings)

        assert stats.count == 10
        assert 1233.0 < stats.min < 1235.0
        assert 1262.0 < stats.max < 1263.0
        assert 1245.0 < stats.median < 1250.0
        assert stats.stdev is not None
        assert stats.stdev > 0


class TestOpsPerSecond:
    """Tests for ops_per_second function."""

    def test_one_microsecond(self):
        """1 microsecond = 1 million ops/sec."""
        assert ops_per_second(1.0) == 1_000_000.0

    def test_thousand_microseconds(self):
        """1000 microseconds = 1000 ops/sec."""
        assert ops_per_second(1000.0) == 1000.0

    def test_realistic_value(self):
        """Realistic latency value."""
        # 15.5 microseconds
        result = ops_per_second(15.5)
        assert result == pytest.approx(64516.129, rel=0.001)

    def test_zero_raises(self):
        """Zero latency should raise ValueError."""
        with pytest.raises(ValueError, match="positive"):
            ops_per_second(0.0)

    def test_negative_raises(self):
        """Negative latency should raise ValueError."""
        with pytest.raises(ValueError, match="positive"):
            ops_per_second(-1.0)


class TestStatsDataclass:
    """Tests for Stats dataclass."""

    def test_creation(self):
        """Stats can be created with all fields."""
        stats = Stats(
            median=100.0,
            p95=150.0,
            p99=180.0,
            min=50.0,
            max=200.0,
            count=10,
            mean=105.0,
            stdev=25.0,
        )
        assert stats.median == 100.0
        assert stats.stdev == 25.0

    def test_stdev_optional(self):
        """stdev can be None."""
        stats = Stats(
            median=100.0,
            p95=100.0,
            p99=100.0,
            min=100.0,
            max=100.0,
            count=1,
            mean=100.0,
            stdev=None,
        )
        assert stats.stdev is None
