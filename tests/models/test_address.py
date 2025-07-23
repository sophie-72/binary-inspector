import unittest
from src.models import Address
from tests.fixtures import ANY_OBJECT

ANY_VALUE = 1
ANOTHER_VALUE = 2


class TestAddressEqual(unittest.TestCase):
    def test_equal_addresses_are_equal(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANY_VALUE)

        self.assertEqual(first_address, second_address)

    def test_different_addresses_are_not_equal(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANOTHER_VALUE)

        self.assertNotEqual(first_address, second_address)

    def test_different_objects_are_not_equal(self):
        first_address = Address(ANY_VALUE)
        second_address = ANY_OBJECT

        self.assertNotEqual(first_address, second_address)


class TestAddressHashing(unittest.TestCase):
    def test_hash_of_equal_addresses_is_same(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANY_VALUE)

        self.assertEqual(hash(first_address), hash(second_address))

    def test_hash_of_different_addresses_is_not_same(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANOTHER_VALUE)

        self.assertNotEqual(hash(first_address), hash(second_address))


class TestAddressConversion(unittest.TestCase):
    def test_to_hex_string_returns_correct_value(self):
        an_address = Address(ANY_VALUE)

        self.assertEqual(an_address.to_hex_string(), hex(ANY_VALUE))


class TestAddressProperty(unittest.TestCase):
    def test_value_property_returns_correct_value(self):
        an_address = Address(ANY_VALUE)

        self.assertEqual(an_address.value, ANY_VALUE)
