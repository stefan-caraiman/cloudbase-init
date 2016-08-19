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

import copy
import uuid

import six

from cloudbaseinit import constant
from cloudbaseinit import exception


class FieldDescriptor(object):

    """Descriptor for all the available fields for a model.

    Fields are exposed as descriptors in order to control access to the
    underlying raw data.
    """

    def __init__(self, field):
        self._field = field
        self._attribute = field.name

    @property
    def field(self):
        """Expose the received field object."""
        return self._field

    def __get__(self, instance, instance_type=None):
        if instance is not None:
            return instance._data.get(self._attribute)
        return self._field

    def __set__(self, instance, value):
        instance._changes[self._attribute] = value


class Field(object):

    """Meta information regarding the data components.

    :param name:       The name of the current piece of information.
    :param default:    Default value for the current field. (default: `None`)
    :param allow_none: Whether the current piece of information is required
                       for the container object or can be missing.
                       (default: `True`)
    """

    def __init__(self, name, default=None, allow_none=True):
        self._name = name
        self._default = default
        self._required = not allow_none
        self._model_class = None

    @property
    def name(self):
        """The name of the current field."""
        return self._name

    @property
    def default(self):
        """Default value for the current field."""
        return self._default

    @property
    def required(self):
        """Whether the current field is required or can be missing."""
        return self._required

    def add_to_class(self, model_class):
        """Replace the `Field` attribute with a named `FieldDescriptor`.

        .. note::
            This method is called  during construction of the `Model`.
        """
        self._model_class = model_class
        model_class._meta.add_field(self)
        setattr(model_class, self._name, FieldDescriptor(self))


class ModelOptions(object):

    """Container for all the model options.

    .. note::
        The current object will be created by the model metaclass.
        All the available options should be passed using a object
        called `Meta`.

        For example::

            class BaseModel(Model):

                class Meta:
                    auto_save = True
                    custom_option = False
                    # ...
    """

    def __init__(self, cls, auto_save=False, **kwargs):
        self.model_class = cls
        self.name = cls.__name__
        self.auto_save = auto_save
        self.additional_keys = set(kwargs.keys())
        for key, value in kwargs.items():
            setattr(self, key, value)

        self._fields = {}
        self._defaults = {}
        self._default_callables = {}

    @property
    def fields(self):
        """All the available fields for the current model."""
        return self._fields

    def add_field(self, field):
        """Add the received field to the model."""
        self.remove_field(field.name)
        self._fields[field.name] = field

        if field.default is not None:
            if six.callable(field.default):
                self._default_callables[field.name] = field.default
            else:
                self._defaults[field.name] = field.default

    def remove_field(self, field_name):
        """Remove the field with the received field name from model."""
        field = self._fields.pop(field_name, None)
        if field is not None and field.default is not None:
            if six.callable(field.default):
                self._default_callables.pop(field, None)
            else:
                self._defaults.pop(field, None)

    def get_defaults(self):
        """Get a dictionary that contains all the available defaults."""
        defaults = self._defaults.copy()
        for field_name, default in self._default_callables.items():
            defaults[field_name] = default()
        return defaults


class BaseModel(type):

    """Metaclass used for properly setting up a new model."""

    def __new__(mcs, name, bases, attrs):
        # Get all the available meta information
        meta_options = {}
        BaseModel._get_meta_options(attrs, meta_options)
        BaseModel._inherit_fields(bases, attrs, meta_options)

        # Initialize the new class and set the magic attributes
        cls = super(BaseModel, mcs).__new__(mcs, name, bases, attrs)

        # Create the ModelOptions object and inject it in the new class
        cls._meta = ModelOptions(cls, **meta_options)

        # Get all the available fields for the current model.
        for name, field in list(cls.__dict__.items()):
            if name.startswith("_"):
                continue
            if isinstance(field, Field):
                field.add_to_class(cls)

        # Create string representation for the current model before finalizing
        setattr(cls, '__str__', lambda self: '%s' % cls.__name__)
        return cls

    @staticmethod
    def _get_meta_options(attrs, meta_options):
        """Obtain all the information passed by `Meta` attribute."""
        meta = attrs.pop('Meta', None)
        if meta:
            for attribute, value in meta.__dict__.items():
                if attribute.startswith('_'):
                    continue
                meta_options[attribute] = value

    @staticmethod
    def _inherit_fields(bases, attrs, meta_options):
        """Inherit any field descriptors.

         The inherit is made by deep copying the underlying field into
         the attributes of the new model.
         """
        for base in bases:
            base_meta = getattr(base, "_meta", None)
            if base_meta is None:
                continue

            for key, attribute in base_meta.__dict__.items():
                if key not in meta_options:
                    meta_options[key] = attribute

            for key, attribute in base.__dict__.items():
                if key in attrs:
                    continue
                if isinstance(attribute, FieldDescriptor):
                    attrs[key] = copy.deepcopy(attribute.field)


@six.add_metaclass(BaseModel)
class Model(object):

    """Container for meta information regarding the data structure."""

    def __init__(self, **fields):
        self._data = self._meta.get_defaults()
        self._changes = {}

        for field_name, value in fields.items():
            setattr(self, field_name, value)

        # Check if everything is alright.
        self.validate()
        self.commit()

    def validate(self):
        """Check if the current model was properly created."""
        for field_name, field in self._meta.fields.items():
            if field.required and field.name not in self._data:
                raise exception.DataProcessingError(
                    "The required field %r is missig." % field_name)

    def commit(self):
        """Apply all the changes on the current model."""
        self._data.update(self._changes)
        self._changes.clear()

    def update(self, fields):
        """Update the value of one or or more fields."""
        self._changes.update(fields)

    def dump(self):
        """Create a dictionary with the content of the current model."""
        return self._data.copy()


class Link(Model):

    """Model that contains information regarding an interface."""

    link_id = Field(name=constant.LINK_ID,
                    default=lambda: str(uuid.uuid1()))
    name = Field(name=constant.NAME)
    mac_address = Field(name=constant.MAC_ADDRESS)
    mtu = Field(name=constant.MTU)
    link_type = Field(name=constant.LINK_TYPE, default=constant.PHY)
    priority = Field(name=constant.PRIORITY, default=0)


class BondLink(Link):

    """Model that contains information regarding an interface from a bond."""

    bond_links = Field(name=constant.BOND_LINKS)
    bond_mode = Field(name=constant.BOND_MODE)
    bond_miimon = Field(name=constant.BOND_MIIMON)
    bond_hash_policy = Field(name=constant.BOND_HASH_POLICY)
    link_type = Field(name=constant.LINK_TYPE, default=constant.BOND)
    priority = Field(name=constant.PRIORITY, default=10)


class VLANLink(Link):

    """Model that contains information regarding an interface from a VLAN."""

    vlan_id = Field(name=constant.VLAN_ID)
    vlan_link = Field(name=constant.VLAN_LINK)
    link_type = Field(name=constant.LINK_TYPE, default=constant.VLAN)
    priority = Field(name=constant.PRIORITY, default=20)


class Subnetwork(Model):

    """Model that contains information regarding a subnetwork."""

    subnet_id = Field(name=constant.SUBNET_ID,
                      default=lambda: str(uuid.uuid1()))
    assigned_to = Field(name=constant.ASSIGNED_TO)
    priority = Field(name=constant.PRIORITY, default=10)
    network_type = Field(name=constant.NETWORK_TYPE, default=constant.MANUAL)


class StaticNetwork(Subnetwork):

    """Model that contains information regarding a static subnetwork."""

    ip_address = Field(name=constant.IP_ADDRESS)
    ip_version = Field(name=constant.IP_VERSION)
    netmask = Field(name=constant.NETMASK)
    gateway = Field(name=constant.GATEWAY)
    broadcast = Field(name=constant.BROADCAST)
    dns = Field(name=constant.DNS, default=[])
    priority = Field(name=constant.PRIORITY, default=0)
    network_type = Field(name=constant.NETWORK_TYPE, default=constant.STATIC)


class Route(Model):

    """Model that contains information regarding a route."""

    route_id = Field(name=constant.ROUTE_ID,
                     default=lambda: str(uuid.uuid1()))
    network = Field(name=constant.NETWORK)
    netmask = Field(name=constant.NETMASK)
    gateway = Field(name=constant.GATEWAY)
    assigned_to = Field(name=constant.ASSIGNED_TO)
