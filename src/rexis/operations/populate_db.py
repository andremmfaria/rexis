import pprint
from typing import Any, Dict, List

from ..facade.malware_bazaar import query_malware_bazaar


def populate_db(query_type: str, query_value: str) -> None:
    def get_ransomware_metadata() -> List[Dict[str, Any]]:
        return query_malware_bazaar(query_type=query_type, query_value=query_value)

    metadata: List[Dict[str, Any]] = get_ransomware_metadata()
    
    return metadata
