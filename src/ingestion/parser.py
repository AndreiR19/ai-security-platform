from src.ingestion.models import AuthEvent

def parse_line(line: str, year: int) -> AuthEvent | None:
    return None