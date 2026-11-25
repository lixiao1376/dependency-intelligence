from pydantic import BaseModel, validator


class User(BaseModel):
    name: str

    @validator("name")
    def name_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be blank")
        return value


def parse_user(payload: dict) -> User:
    return User.parse_obj(payload)

