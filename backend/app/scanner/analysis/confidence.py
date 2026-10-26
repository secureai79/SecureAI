def confidence_label(value: float | None) -> str:
    if value is None:
        return "POSSIBLE"
    if value >= 0.90:
        return "CONFIRMED"
    if value >= 0.70:
        return "LIKELY"
    return "POSSIBLE"
