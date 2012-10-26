class Authorization(object):
    """
    A base class that provides no permissions checking.
    """
    def __get__(self, instance, owner):
        """
        Makes ``Authorization`` a descriptor of ``ResourceOptions`` and creates
        a reference to the ``ResourceOptions`` object that may be used by
        methods of ``Authorization``.
        """
        self.resource_meta = instance
        return self

    def is_authorized(self, request, object=None):
        """
        Checks if the user is authorized to perform the request. If ``object``
        is provided, it can do additional row-level checks.

        Should return either ``True`` if allowed, ``False`` if not or an
        ``HttpResponse`` if you need something custom.
        """
        return True

    def apply_limits(self, request, object_list):
        return object_list

    def __and__(a,b):
        return IntersectionAuthorization(a,b)

    def __or__(a,b):
        return UnionAuthorization(a,b)


class ReadOnlyAuthorization(Authorization):
    """
    Default Authentication class for ``Resource`` objects.

    Only allows GET requests.
    """

    def is_authorized(self, request, object=None):
        """
        Allow any ``GET`` request.
        """
        if request.method == 'GET':
            return True
        else:
            return False


class DjangoAuthorization(Authorization):
    """
    Uses permission checking from ``django.contrib.auth`` to map
    ``POST / PUT / DELETE / PATCH`` to their equivalent Django auth
    permissions.
    """
    def is_authorized(self, request, object=None):
        # GET-style methods are always allowed.
        if request.method in ('GET', 'OPTIONS', 'HEAD'):
            return True

        klass = self.resource_meta.object_class

        # If it doesn't look like a model, we can't check permissions.
        if not klass or not getattr(klass, '_meta', None):
            return True

        permission_map = {
            'POST': ['%s.add_%s'],
            'PUT': ['%s.change_%s'],
            'DELETE': ['%s.delete_%s'],
            'PATCH': ['%s.add_%s', '%s.change_%s', '%s.delete_%s'],
        }
        permission_codes = []

        # If we don't recognize the HTTP method, we don't know what
        # permissions to check. Deny.
        if request.method not in permission_map:
            return False

        for perm in permission_map[request.method]:
            permission_codes.append(perm % (klass._meta.app_label, klass._meta.module_name))

        # User must be logged in to check permissions.
        if not hasattr(request, 'user'):
            return False

        return request.user.has_perms(permission_codes)

class IntersectionAuthorization(Authorization):
    """
    Checks that all the provided Authorization methods are authorized
    """
    def __init__(self, *backends, **kwargs):
        super(Authorization, self).__init__(**kwargs)
        self.backends = backends

    def is_authorized(self, request, object=None):
        # Intersection method
        for backend in self.backends:
            authorized = backend.is_authorized(request, object)
            if not authorized:
                return False
        return True

    def apply_limits(self, request, object_list):
        result = self.backends[0].apply_limits(request, object_list)
        for backend in self.backends[1:]:
            result = result & backend.apply_limits(request, backend.apply_limits(request, object_list))
        return result

class UnionAuthorization(Authorization):
    """
    Checks that any of the provided Authorization methods are authorized
    """
    def __init__(self, *backends, **kwargs):
        super(Authorization, self).__init__(**kwargs)
        self.backends = backends

    def is_authorized(self, request, object=None):
        # Union method
        for backend in self.backends:
            authorized = backend.is_authorized(request, object)
            if authorized:
                return True
        return False

    def apply_limits(self, request, object_list):
        result = self.backends[0].apply_limits(request, object_list)
        for backend in self.backends[1:]:
            result = result | backend.apply_limits(request, object_list)
        return result
