# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# pylint: disable=protected-access

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit import model


class TestFieldDescriptor(unittest.TestCase):

    def test_field_access(self):
        instance = mock.Mock()
        field = mock.sentinel.field
        field_descriptor = model.FieldDescriptor(field)

        self.assertIs(field, field_descriptor.__get__(None))

        field_descriptor.__get__(instance)
        instance._data.get.assert_called_once_with(field.name)

    def test_set_field(self):
        instance = mock.MagicMock()
        field = mock.sentinel.field
        field_descriptor = model.FieldDescriptor(field)

        instance._data = {}
        field_descriptor.__set__(instance, mock.sentinel.value)
        self.assertIs(instance._data[field.name], mock.sentinel.value)

    def test_field_property(self):
        field = mock.sentinel.field
        field_descriptor = model.FieldDescriptor(field)

        self.assertIs(field_descriptor.field, field)


class TestField(unittest.TestCase):

    def test_properties(self):
        field = model.Field(name=mock.sentinel.name, allow_none=True,
                            default=mock.sentinel.default)

        self.assertIs(field.name, mock.sentinel.name)
        self.assertIs(field.default, mock.sentinel.default)
        self.assertFalse(field.required)

    @mock.patch("cloudbaseinit.model.FieldDescriptor")
    def test_add_to_class(self, mock_field_descriptor):
        field = model.Field(name="test_add_to_class")
        model_class = mock.Mock()

        field.add_to_class(model_class)

        mock_field_descriptor.assert_called_once_with(field)
        self.assertIsNotNone(getattr(model_class, "test_add_to_class"))


class TestModelOptions(unittest.TestCase):

    def test_initialization(self):
        mock.sentinel.cls.__name__ = mock.sentinel.cls.name
        model_options = model.ModelOptions(cls=mock.sentinel.cls)

        self.assertIs(model_options._model_class, mock.sentinel.cls)
        self.assertEqual(model_options._name, mock.sentinel.cls.name)

    @mock.patch("six.callable")
    @mock.patch("cloudbaseinit.model.ModelOptions.remove_field")
    def _test_add_field(self, mock_remove_field, mock_callable,
                        callable_default):
        model_options = model.ModelOptions(self.__class__)
        test_field = model.Field(name=mock.sentinel.name, allow_none=True,
                                 default=mock.sentinel.default)
        mock_callable.return_value = callable_default

        model_options.add_field(test_field)

        mock_remove_field.assert_called_once_with(mock.sentinel.name)
        self.assertIs(model_options._fields[test_field.name], test_field)
        if callable_default:
            self.assertIs(model_options._default_callables[test_field.name],
                          mock.sentinel.default)
        else:
            self.assertIs(model_options._defaults[test_field.name],
                          mock.sentinel.default)

    def test_add_field(self):
        self._test_add_field(callable_default=False)
        self._test_add_field(callable_default=True)

    @mock.patch("six.callable")
    def _test_remove_field(self, mock_callable, callable_default):
        mock_callable.return_value = callable_default
        model_options = model.ModelOptions(self.__class__)
        test_field = model.Field(name=mock.sentinel.name, allow_none=True,
                                 default=mock.sentinel.default)
        model_options.add_field(test_field)

        model_options.remove_field(test_field.name)

        self.assertNotIn(test_field.name, model_options._fields)
        if callable_default:
            self.assertNotIn(test_field.name, model_options._default_callables)
        else:
            self.assertNotIn(test_field.name, model_options._defaults)

    def test_remove_field(self):
        self._test_remove_field(callable_default=False)
        self._test_remove_field(callable_default=True)

    def test_get_defaults(self):
        default = lambda: mock.sentinel.default
        test_field = model.Field(name=mock.sentinel.name, allow_none=True,
                                 default=default)
        model_options = model.ModelOptions(self.__class__)
        model_options.add_field(test_field)

        defaults = model_options.get_defaults()

        self.assertEqual(defaults, {mock.sentinel.name: mock.sentinel.default})


class TestBaseModel(unittest.TestCase):

    def test_create_model(self):

        class _Test(model.Model):
            field1 = model.Field(name="field1", default=1)

        self.assertTrue(hasattr(_Test, "_meta"))
        self.assertEqual(_Test().field1, 1)

    def test_inherit_fields(self):

        class _TestBase(model.Model):
            field1 = model.Field(name="field1", default=1)
            field2 = model.Field(name="field2")

        class _Test(_TestBase):
            field2 = model.Field(name="field2", default=2)

        class _FinalTest(_Test):
            field3 = model.Field(name="field3", allow_none=False)

        final_test = _FinalTest(field3=3)
        self.assertEqual(final_test.field1, 1)
        self.assertEqual(final_test.field2, 2)
        self.assertEqual(final_test.field3, 3)


class TestModel(unittest.TestCase):

    class _Test(model.Model):
        field1 = model.Field(name="field1")
        field2 = model.Field(name="field2", allow_none=False)

    def test_validate(self):
        self.assertRaises(exception.DataProcessingError, self._Test, field1=1)

    def test_update(self):
        test = self._Test(field1=1, field2=2)
        test.update({"field1": mock.sentinel.field1,
                     "field2": mock.sentinel.field2})

        self.assertIs(test.field1, mock.sentinel.field1)
        self.assertIs(test.field2, mock.sentinel.field2)

    def test_dump(self):
        fields = {"field1": 1, "field2": 2}
        test = self._Test(**fields)

        self.assertEqual(test.dump(), fields)
