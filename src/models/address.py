"""Represents an address."""


class Address:
    """Represents an address."""

    def __init__(self, value: int) -> None:
        self.__value = value

    @classmethod
    def from_hex_string(cls, hex_string: str) -> "Address":
        return Address(int(hex_string, 16))

    def __eq__(self, other) -> bool:
        if not isinstance(other, Address):
            return False

        return self.__value == other.value

    def __hash__(self) -> int:
        return hash(self.__value)

    @property
    def value(self) -> int:
        """Get the address value."""
        return self.__value

    def to_hex_string(self) -> str:
        """Convert the address to a hex string."""
        return hex(self.__value)
