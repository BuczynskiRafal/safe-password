import os
import yaml
import pytest
from pathlib import Path
from password_validators.validators import (
    HasNumberValidator,
    HasSpecialCharactersValidator,
    LengthValidator,
    HasUpperCharactersValidator,
    HasLowerCharactersValidator,
    HaveIbeenPwndValidator,
    PasswordValidator,
)
from password_validators.exceptions.exceptions import ValidationError
from password_validators.exceptions.messages import exceptions


class TestHasNumberValidator:
    validator_true = HasNumberValidator("qwerty1.!")
    validator_false = HasNumberValidator("qwerty.!")

    def test_if_has_number_validator_positive(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_has_numbers_validator_positive(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_has_numbers_validator_negative(self, validator=validator_false):
        assert validator.is_validate() is False

    def test_is_valid_param_true(self, validator=validator_true):
        assert validator.is_valid is True
        assert validator.error is None

    def test_is_valid_param_false(self, validator=validator_false):
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(ValidationError(exceptions["ValidationError"]["has_number_validator"]))


class TestHasSpecialCharactersValidator:
    validator_true = HasSpecialCharactersValidator("qwerty123.!@#")
    validator_false = HasSpecialCharactersValidator("qwerty123")

    def test_if_has_one_special_character(self):
        validator = HasSpecialCharactersValidator("qwerty123.")
        assert validator.is_validate() is True

    def test_if_has_a_few_special_character(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_has_no_special_character(self, validator=validator_false):
        assert validator.is_validate() is False

    def test_is_valid_param_true(self, validator=validator_true):
        assert validator.is_valid is True
        assert validator.error is None

    def test_is_valid_param_false(self, validator=validator_false):
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(
            ValidationError(exceptions["ValidationError"]["has_special_character"])
        )


class TestHasUpperCharactersValidator:
    validator_true = HasUpperCharactersValidator("QwERTy123.!")
    validator_false = HasUpperCharactersValidator("qwerty123.!")

    def test_if_has_one_upper_character(self):
        validator = HasUpperCharactersValidator("Qwerty123.!")
        assert validator.is_validate() is True

    def test_if_has_a_few_upper_characters(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_has_no_upper_character(self, validator=validator_false):
        assert validator.is_validate() is False

    def test_is_valid_param_true(self, validator=validator_true):
        assert validator.is_valid is True
        assert validator.error is None

    def test_is_valid_param_false(self, validator=validator_false):
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(
            ValidationError(exceptions["ValidationError"]["has_upper_characters"])
        )


class TestHasLowerCharactersValidator:
    validator_true = HasLowerCharactersValidator("qweTy123.!")
    validator_false = HasLowerCharactersValidator("QWERTY123.!")

    def test_if_has_one_lower_character(self):
        validator = HasLowerCharactersValidator("qwerTy123.!")
        assert validator.is_validate() is True

    def test_if_has_a_few_lower_characters(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_has_no_lower_character(self, validator=validator_false):
        assert validator.is_validate() is False

    def test_is_valid_param_true(self, validator=validator_true):
        assert validator.is_valid is True
        assert validator.error is None

    def test_is_valid_param_false(self, validator=validator_false):
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(
            ValidationError(exceptions["ValidationError"]["has_lower_characters"])
        )


class TestLengthValidator:
    validator_true = LengthValidator("qwerty123.!")
    validator_false = LengthValidator("qwerty")

    def test_if_length_password_is_eight(self):
        validator = LengthValidator("qwerty1!")
        assert validator.is_validate() is True

    def test_if_length_password_is_more_than_eight(self, validator=validator_true):
        assert validator.is_validate() is True

    def test_if_length_password_is_less_than_eight(self, validator=validator_false):
        assert validator.is_validate() is False

    def test_is_valid_param_true(self, validator=validator_true):
        assert validator.is_valid is True
        assert validator.error is None

    def test_is_valid_param_false(self, validator=validator_false):
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(
            ValidationError(exceptions["ValidationError"]["long_enough"])
        )


class TestHaveIbeenPwndValidator:
    def test_have_i_been_pwnd_validator_positive(self, requests_mock):
        # hash: B1B3773A05C0ED0176787A4F1574FF0075F7521E
        data = "63A05C0ED0176787A4F1574FF0075F7521E:10556095\n\r7387376AFD1B3DAB553D439C8A7D7CDDED1:3"
        requests_mock.get("https://api.pwnedpasswords.com/range/B1B37", text=data)
        validator = HaveIbeenPwndValidator("qwerty")
        assert validator.is_validate() is True
        assert validator.is_valid is True
        assert validator.error is None

    def test_have_i_been_pwnd_validator_negative(self, requests_mock):
        # hash: B1B3773A05C0ED0176787A4F1574FF0075F7521E
        data = "73A05C0ED0176787A4F1574FF0075F7521E:10556095\n\r7387376AFD1B3DAB553D439C8A7D7CDDED1:3"
        requests_mock.get("https://api.pwnedpasswords.com/range/B1B37", text=data)
        validator = HaveIbeenPwndValidator("qwerty")
        assert validator.is_validate() is False
        assert validator.is_valid is False
        assert validator.error is not None
        assert str(validator.error) == str(
            ValidationError(exceptions["ValidationError"]["leaked_password"])
        )


class TestPasswordValidator:
    def test_password_validator_positive(self):
        validator = PasswordValidator("Qwerty123.!")
        assert validator.is_validate() is True
        assert validator.is_valid is True
        assert validator.errors is None

    def test_password_validator_positive_errors_is_none(self):
        validator = PasswordValidator("Qwerty123.!")
        assert validator.errors is None

    def test_password_validator_negative(self):
        validator = PasswordValidator("qwerty123.!")
        assert validator.is_validate() is False
        assert validator.is_valid is False
        assert validator.errors is not None
        assert type(validator.error) is list
        assert len(validator.error) >= 1

    def test_password_validator_checking_all_requirements(self):
        requirements = [
            HasNumberValidator,
            LengthValidator,
            HasSpecialCharactersValidator,
            HasUpperCharactersValidator,
            HasLowerCharactersValidator,
            HaveIbeenPwndValidator,
        ]
        validator = PasswordValidator("Qwerty123.!")
        assert validator.validators == requirements
        assert len(validator.validators) > 0
        assert type(validator.validators) is list
