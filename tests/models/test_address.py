import unittest
from src.models.address import Address
from tests.fixtures import ANY_OBJECT

ANY_VALUE = 1
ANOTHER_VALUE = 2


class TestAddress(unittest.TestCase):
    def setUp(self):
        self.an_address = Address(ANY_VALUE)

    def test_creating_an_address_from_hex_string(self):
        an_address_hex_string = hex(ANY_VALUE)

        result = Address.from_hex_string(an_address_hex_string)

        self.assertEqual(result.value, ANY_VALUE)

    def test_equal_addresses_are_equal(self):
        another_address = Address(ANY_VALUE)

        self.assertEqual(self.an_address, another_address)

    def test_different_addresses_are_not_equal(self):
        another_address = Address(ANOTHER_VALUE)

        self.assertNotEqual(self.an_address, another_address)

    def test_different_objects_are_not_equal(self):
        self.assertNotEqual(self.an_address, ANY_OBJECT)

    def test_hash_of_equal_addresses_is_same(self):
        another_address = Address(ANY_VALUE)

        self.assertEqual(hash(self.an_address), hash(another_address))

    def test_hash_of_different_addresses_is_not_same(self):
        another_address = Address(ANOTHER_VALUE)

        self.assertNotEqual(hash(self.an_address), hash(another_address))

    def test_to_hex_string_returns_correct_value(self):
        self.assertEqual(self.an_address.to_hex_string(), hex(ANY_VALUE))

    def test_value_property_returns_correct_value(self):
        self.assertEqual(self.an_address.value, ANY_VALUE)
