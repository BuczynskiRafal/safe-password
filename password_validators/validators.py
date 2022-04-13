"""Collection of password validators."""
import os
import requests
import yaml
from hashlib import sha1
from abc import ABC, abstractmethod
from pathlib import Path

from password_validators.exceptions.exceptions import ValidationError
from password_validators.exceptions.messages import exceptions


# BASE_DIR = Path(__file__).resolve().parent
# FILEPATH = os.path.join(BASE_DIR, "exceptions", "messages" + "." + "yaml")
#
# with open(FILEPATH, "r") as file:
#     exceptions = yaml.safe_load(file)


class Validator(ABC):
    """Interface for validators"""

    def __init__(self) -> None:
        """Force implementing __init__ method"""

    @abstractmethod
    def is_validate(self):
        """Force implementing is_valid method"""


class HasNumberValidator:
    """Validator checking if number appear in password."""

    def __init__(self, password) -> None:
        self.password = password
        self.is_valid = HasNumberValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(
                exceptions["ValidationError"]["has_number_validator"]
            )

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: has number in password
        """
        for number in range(10):
            if str(number) in list(self.password):
                return True
        return False


class HasSpecialCharactersValidator(Validator):
    """Validator checking if special character appear in password."""

    def __init__(self, password) -> None:
        self.password = password
        self.is_valid = HasSpecialCharactersValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(
                exceptions["ValidationError"]["has_special_character"]
            )

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: has special character in password
        """
        return any(not character.isalnum() for character in self.password)


class HasUpperCharactersValidator(Validator):
    """Validator checking if upper character appear in password."""

    def __init__(self, password):
        self.password = password
        self.is_valid = HasUpperCharactersValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(
                exceptions["ValidationError"]["has_upper_characters"]
            )

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: has upper character in password
        """
        return any(character.isupper() for character in self.password)


class HasLowerCharactersValidator(Validator):
    """Validator checking if lower character appear in password."""

    def __init__(self, password):
        self.password = password
        self.is_valid = HasLowerCharactersValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(
                exceptions["ValidationError"]["has_lower_characters"]
            )

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: has lower character in password
        """
        return any(character.islower() for character in self.password)


class LengthValidator(Validator):
    """Validator checking if string is long enough."""

    def __init__(self, password, min_length=8) -> None:
        self.password = password
        self.min_length = min_length
        self.is_valid = LengthValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(exceptions["ValidationError"]["long_enough"])

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: password is long enough
        """
        return len(self.password) >= self.min_length


class HaveIbeenPwndValidator(Validator):
    """Validator checking if password are not leaked."""

    def __init__(self, password) -> None:
        self.password = password
        self.is_valid = HaveIbeenPwndValidator.is_validate(self)
        self.error = None

        if self.is_valid is False:
            self.error = ValidationError(
                exceptions["ValidationError"]["leaked_password"]
            )

    def is_validate(self):
        """Check if password is valid.

        :return:
            bool: password is safe
        """
        hash_code = sha1(self.password.encode("utf-8")).hexdigest().upper()
        url = "https://api.pwnedpasswords.com/range/" + hash_code[:5]
        response = requests.get(url)
        for line in response.text.splitlines():
            found_hash = line.split(":")[0]
            if found_hash == hash_code[5:]:
                return False
        return True


class PasswordValidator:
    """Validator checking if password passed all requirements."""

    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            HasNumberValidator,
            LengthValidator,
            HasSpecialCharactersValidator,
            HasUpperCharactersValidator,
            HasLowerCharactersValidator,
            HaveIbeenPwndValidator,
        ]
        self.errors = None
        self.is_valid = PasswordValidator.is_validate(self)
        if self.is_valid is False:
            self.error = PasswordValidator.update_exceptions(self)

    def is_validate(self):
        """Checks if password is valid

        :rtype:
            bool: return true if password passed all password validation requirements
        """
        for class_name in self.validators:
            validator = class_name(self.password)
            if validator.is_valid is False:
                return False
        return True

    def update_exceptions(self):
        """
        Update all exceptions to list
        """
        self.errors = []
        for class_name in self.validators:
            validator = class_name(self.password)
            if validator.error is not None:
                self.errors.append(validator.error)
        return self.errors



