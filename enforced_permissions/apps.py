import logging
from django.apps import apps, AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Model
from django.db.models import signals
from django.db.models.signals import post_migrate

logger = logging.getLogger(__name__)


class EnforcedPermissionsAppConfig(AppConfig):

    name = 'enforced_permissions'
    verbose_name = 'Enforced Permissions'

    def ready(self):
        super(EnforcedPermissionsAppConfig, self).ready()
        post_migrate.connect(do_enforced_permissions, sender=self)


def do_enforced_permissions(app_config, **kwargs):
    from django.contrib.auth.models import Group, Permission
    from django.contrib.auth import get_permission_codename
    from django.contrib.contenttypes.models import ContentType
    errors = []
    
    groups = settings.ENFORCED_PERMISSIONS['groups']
    exclude = settings.ENFORCED_PERMISSIONS.get('exclude', [])
    perms = settings.ENFORCED_PERMISSIONS['permissions']
    group_objects = {}
    
    groups_count = Group.objects.all().count()

    if not groups_count:
        if getattr(settings, 'IGNORE_PERMS', False):
            return
        else:
            print(
                'No groups exist. Please create the following: {} and assign users. ' \
                  'Temporarily use "IGNORE_PERMS = True" to ignore if you need to access the shell'.format(
                ','.join(groups.values()))
            )
            exit()

    group_errors = []
    
    for group, group_name in groups.items():
        try:
            group_objects.update({
                group: Group.objects.get(name=group_name)
            })
        except Group.DoesNotExist:
            group_errors.append(group)
        
        if len(group_errors):
            raise ImproperlyConfigured('The following groups do not exist: {}'.format(','.join(group_errors)))
    
    def is_excluded(l):
        # TODO Allow wildcards
        return l in exclude

    if len(perms) != len(list(set(perms))):
        raise ImproperlyConfigured("Duplicate entries in ENFORCED_PERMISSIONS")

    missing_apps = []
    all_app_labels = list(set([x.split('.')[0] for x in perms.keys()]))
    for app_label in all_app_labels:
        try:
            apps.get_app_config(app_label).models_module
        except ImproperlyConfigured:
            missing_apps.append(app_label)
    if missing_apps:
        raise ImproperlyConfigured("ENFORCED_PERMISSIONS refers to non-existent app: {}".format(','.join(missing_apps)))
    
    all_models = [x for x in perms if not x.endswith('.*')]
    # TODO check for models that don't exist
    
    for model in apps.get_models():
        meta = model._meta

        if not issubclass(model, Model):
            continue

        label = '{}.{}'.format(meta.app_label, meta.model_name)
        label_wildcard = '{}.*'.format(meta.app_label)
        if is_excluded(label) or is_excluded(label_wildcard):
            continue
        
        if label in perms:
            model_perms = perms[label]
        elif label_wildcard in perms:
            model_perms = perms[label_wildcard]
        else:
            errors.append(
                "No permissions defined for {} in settings.ENFORCED_PERMISSIONS".format(label)
            )
            continue

        for group in groups:
            group_obj = group_objects.get(group)
            if type(model_perms) == bool:
                model_group_perms = model_perms
            elif group in model_perms:
                model_group_perms = model_perms[group]
            elif '*' in model_perms:
                model_group_perms = model_perms['*']
            else:
                errors.append("No permissions defined for group {} and model {} "
                              "in settings.ENFORCED_PERMISSIONS".format(group, label))
                continue
            
            # Should probably accommodate duck typing somehow but this is simpler
            if isinstance(model_group_perms, dict):
                add, change, delete = model_group_perms.values()
            elif isinstance(model_group_perms, list):
                add, change, delete = model_group_perms
            elif isinstance(model_group_perms, bool):
                add, change, delete = [model_group_perms] * 3
            else:
                errors.append(TypeError('Invalid model permissions for {}'.format(label)))
                continue

            for action, should_has_perm in [('add', add), ('change', change), ('delete', delete), ]:
                codename = get_permission_codename(action, model._meta)
                content_type = ContentType.objects.get_for_model(model)
                has_perm = group_obj.permissions.filter(codename=codename, content_type=content_type).exists()
                if has_perm != should_has_perm:
                    try:
                        perm = Permission.objects.get(codename=codename, content_type=content_type)
                    except Permission.DoesNotExist:
                        app_config = model._meta.app_config
                        signals.post_migrate.send(
                            sender=app_config,
                            app_config=app_config,
                        )
                        perm = Permission.objects.get(
                            codename=codename,
                            content_type=content_type,
                        )
                    if should_has_perm:
                        print('Adding: permission {} for {}'.format(label, group))
                        group_obj.permissions.add(perm)
                    else:
                        print('Removing: group {} should not have permission {} for {}.'.format(
                            group,
                            codename,
                            label,
                        ))
                        group_obj.permissions.remove(perm)

    if errors:
        raise ImproperlyConfigured('\n'.join(errors))
