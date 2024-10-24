import dataclasses
import datetime
import uuid


@dataclasses.dataclass
class Message:
    content: str
    created_at: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)

    def __str__(self) -> str:
        return self.content


@dataclasses.dataclass
class User:
    username: str
    id: uuid.UUID = dataclasses.field(default_factory=uuid.uuid4)
    messages: list[Message] = dataclasses.field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.username} {self.id}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, User):
            return False
        return self.id == other.id
