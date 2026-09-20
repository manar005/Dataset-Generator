# Scale DESIGN.md profile weights to the actual number of seeds per label.

from __future__ import annotations

from src.config import PROFILE_NAMES, Label, ProfileName, V1_PROFILE_LABEL_COUNTS

# Original DESIGN.md quotas are 1,000-base weights, not fixed corpus sizes.
PROFILE_WEIGHTS: dict[Label, dict[ProfileName, int]] = {
    "legitimate": {name: V1_PROFILE_LABEL_COUNTS[name]["legitimate"] for name in PROFILE_NAMES},
    "phishing": {name: V1_PROFILE_LABEL_COUNTS[name]["phishing"] for name in PROFILE_NAMES},
}


def allocate_profile_counts(n: int, label: Label) -> dict[ProfileName, int]:
    """Allocate integer profile counts for one label using largest remainder.

    Every profile stays represented when n >= number of profiles.
    Ties break by stable PROFILE_NAMES order, not by email text.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    weights = [PROFILE_WEIGHTS[label][name] for name in PROFILE_NAMES]
    return _largest_remainder(weights, n, PROFILE_NAMES)


def _largest_remainder(
    weights: list[int],
    n: int,
    names: tuple[ProfileName, ...],
) -> dict[ProfileName, int]:
    k = len(names)
    if n == 0:
        return {name: 0 for name in names}
    if n < k:
        raise ValueError(f"Need at least {k} seeds to represent every profile, got {n}")
    total_w = sum(weights)
    if total_w <= 0:
        raise ValueError("Profile weights must be positive")
    quotas = [n * weight / total_w for weight in weights]
    floors = [int(quota) for quota in quotas]
    remainders = [quota - floor for quota, floor in zip(quotas, floors, strict=True)]
    leftover = n - sum(floors)
    # Largest remainder first; ties keep earlier PROFILE_NAMES order.
    order = sorted(range(k), key=lambda i: (-remainders[i], i))
    for index in order[:leftover]:
        floors[index] += 1
    if n >= k:
        zeros = [i for i, value in enumerate(floors) if value == 0]
        for zero in zeros:
            donor = max(range(k), key=lambda i: (floors[i], -i))
            if floors[donor] <= 1:
                break
            floors[donor] -= 1
            floors[zero] += 1
    allocated = {names[i]: floors[i] for i in range(k)}
    if sum(allocated.values()) != n:
        raise ValueError(f"Allocation {sum(allocated.values())} != {n}")
    if n >= k and any(value < 1 for value in allocated.values()):
        raise ValueError(f"A profile was left unrepresented for n={n}: {allocated}")
    return allocated


def allocate_profiles_for_counts(counts_by_label: dict[Label, int]) -> dict[ProfileName, dict[Label, int]]:
    """Return profile -> label -> count, summing to each label's seed count."""
    result: dict[ProfileName, dict[Label, int]] = {name: {} for name in PROFILE_NAMES}
    for label, n in counts_by_label.items():
        allocated = allocate_profile_counts(n, label)
        for name, value in allocated.items():
            result[name][label] = value
    return result
