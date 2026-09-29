"""Project authorization is separate from global tool scopes and path validation."""
from .common import RuntimeFault

class ProjectAccess:
    def __init__(self, principals: dict):
        self.principals = principals
        if not isinstance(principals, dict):
            raise ValueError('principals must be an explicit mapping')
        for owner, record in principals.items():
            if not isinstance(owner, str) or not owner or not isinstance(record, dict):
                raise ValueError('Invalid principal')
            projects = record.get('projects', [])
            if not isinstance(projects, list) or any(not isinstance(p,str) or not p or p == '*' for p in projects):
                raise ValueError('Projects must be exact named grants, not a wildcard')

    def require(self, owner: str, project: str) -> None:
        record = self.principals.get(owner, {})
        if record.get('revoked') or project not in record.get('projects', []):
            raise RuntimeFault('PROJECT_DENIED', 'Identity is not authorized for this project.')
