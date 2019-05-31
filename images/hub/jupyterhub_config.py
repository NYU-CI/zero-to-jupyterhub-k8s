import os
import glob
from tornado.httpclient import AsyncHTTPClient
from kubernetes import client

from z2jh import get_config_string, get_config, get_secret, set_config_if_not_none
from jupyterhub.utils import url_path_join

# Configure JupyterHub to use the curl backend for making HTTP requests,
# rather than the pure-python implementations. The default one starts
# being too slow to make a large number of requests to the proxy API
# at the rate required.
AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

c.JupyterHub.spawner_class = 'kubespawner.KubeSpawner'

# Connect to a proxy running in a different pod
c.ConfigurableHTTPProxy.api_url = 'http://{}:{}'.format(os.environ['PROXY_API_SERVICE_HOST'], int(os.environ['PROXY_API_SERVICE_PORT']))
c.ConfigurableHTTPProxy.should_start = False

# Do not shut down user pods when hub is restarted
c.JupyterHub.cleanup_servers = False

# Check that the proxy has routes appropriately setup
# This isn't the best named setting :D
c.JupyterHub.last_activity_interval = 60

# Max number of servers that can be spawning at any one time
c.JupyterHub.concurrent_spawn_limit = get_config('hub.concurrent-spawn-limit')

# Don't wait at all before redirecting a spawning user to the progress page
c.JupyterHub.tornado_settings = {
    'slow_spawn_timeout': 0,
}

# Max number of consecutive failures before the Hub restarts itself
# requires jupyterhub 0.9.2
c.Spawner.consecutive_failure_limit = get_config('hub.consecutive-failure-limit', 0)

active_server_limit = get_config('hub.active-server-limit', None)
if active_server_limit is not None:
    c.JupyterHub.active_server_limit = int(active_server_limit)

c.JupyterHub.ip = os.environ['PROXY_PUBLIC_SERVICE_HOST']
c.JupyterHub.port = int(os.environ['PROXY_PUBLIC_SERVICE_PORT'])

# the hub should listen on all interfaces, so the proxy can access it
c.JupyterHub.hub_ip = '0.0.0.0'

c.KubeSpawner.common_labels = get_config('kubespawner.common-labels')

c.KubeSpawner.namespace = os.environ.get('POD_NAMESPACE', 'default')

c.KubeSpawner.start_timeout = get_config('singleuser.start-timeout')

# Use env var for this, since we want hub to restart when this changes
c.KubeSpawner.image_spec = os.environ['SINGLEUSER_IMAGE']

c.KubeSpawner.image_pull_policy = get_config('singleuser.image-pull-policy')

c.KubeSpawner.image_pull_secrets = get_config('singleuser.image-pull-secret-name', None)

c.KubeSpawner.events_enabled = get_config('singleuser.events', False)

c.KubeSpawner.extra_annotations = get_config('singleuser.extra-annotations', {})

c.KubeSpawner.extra_labels = get_config('singleuser.extra-labels', {})

c.KubeSpawner.uid = get_config('singleuser.uid')
c.KubeSpawner.fs_gid = get_config('singleuser.fs-gid')

service_account_name = get_config('singleuser.service-account-name', None)
if service_account_name:
    c.KubeSpawner.service_account = service_account_name

c.KubeSpawner.node_selector = get_config('singleuser.node-selector')
# Configure dynamically provisioning pvc
storage_type = get_config('singleuser.storage.type')
if storage_type == 'dynamic':
    pvc_name_template = get_config('singleuser.storage.dynamic.pvc-name-template')
    volume_name_template = get_config('singleuser.storage.dynamic.volume-name-template')
    c.KubeSpawner.pvc_name_template = pvc_name_template
    c.KubeSpawner.storage_pvc_ensure = True
    storage_class = get_config('singleuser.storage.dynamic.storage-class', None)
    if storage_class:
        c.KubeSpawner.storage_class = storage_class
    c.KubeSpawner.storage_access_modes = get_config('singleuser.storage.dynamic.storage-access-modes')
    c.KubeSpawner.storage_capacity = get_config('singleuser.storage.capacity')

    # Add volumes to singleuser pods
    c.KubeSpawner.volumes = [
        {
            'name': volume_name_template,
            'persistentVolumeClaim': {
                'claimName': pvc_name_template
            }
        }
    ]
    c.KubeSpawner.volume_mounts = [
        {
            'mountPath': get_config('singleuser.storage.home_mount_path'),
            'name': volume_name_template
        }
    ]
elif storage_type == 'static':
    pvc_claim_name = get_config('singleuser.storage.static.pvc-name')
    c.KubeSpawner.volumes = [{
        'name': 'home',
        'persistentVolumeClaim': {
            'claimName': pvc_claim_name
        }
    }]

    c.KubeSpawner.volume_mounts = [{
        'mountPath': get_config('singleuser.storage.home_mount_path'),
        'name': 'home',
        'subPath': get_config('singleuser.storage.static.sub-path')
    }]

c.KubeSpawner.volumes.extend(get_config('singleuser.storage.extra-volumes', []))
c.KubeSpawner.volume_mounts.extend(get_config('singleuser.storage.extra-volume-mounts', []))

lifecycle_hooks = get_config('singleuser.lifecycle-hooks')
if lifecycle_hooks:
    c.KubeSpawner.lifecycle_hooks = lifecycle_hooks

init_containers = get_config('singleuser.init-containers')
if init_containers:
    c.KubeSpawner.init_containers.extend(init_containers)

# Gives spawned containers access to the API of the hub
c.KubeSpawner.hub_connect_ip = os.environ['HUB_SERVICE_HOST']
c.KubeSpawner.hub_connect_port = int(os.environ['HUB_SERVICE_PORT'])

c.JupyterHub.hub_connect_ip = os.environ['HUB_SERVICE_HOST']
c.JupyterHub.hub_connect_port = int(os.environ['HUB_SERVICE_PORT'])

c.KubeSpawner.mem_limit = get_config('singleuser.memory.limit')
c.KubeSpawner.mem_guarantee = get_config('singleuser.memory.guarantee')
c.KubeSpawner.cpu_limit = get_config('singleuser.cpu.limit')
c.KubeSpawner.cpu_guarantee = get_config('singleuser.cpu.guarantee')
c.KubeSpawner.extra_resource_limits = get_config('singleuser.extra-resource.limits', {})
c.KubeSpawner.extra_resource_guarantees = get_config('singleuser.extra-resource.guarantees', {})

profile_list_callable = get_config_string("singleuser.profile_list_callable")

if profile_list_callable:
    exec(profile_list_callable)
else:
    profile_list = get_config('singleuser.profile_list')
    if profile_list:
        c.KubeSpawner.profile_list = profile_list

# Allow switching authenticators easily
auth_type = get_config('auth.type')
email_domain = 'local'

if auth_type == 'google':
    c.JupyterHub.authenticator_class = 'oauthenticator.GoogleOAuthenticator'
    c.GoogleOAuthenticator.client_id = get_config('auth.google.client-id')
    c.GoogleOAuthenticator.client_secret = get_config('auth.google.client-secret')
    c.GoogleOAuthenticator.oauth_callback_url = get_config('auth.google.callback-url')
    set_config_if_not_none(c.GoogleOAuthenticator, 'hosted_domain', 'auth.google.hosted-domain')
    c.GoogleOAuthenticator.login_service = get_config('auth.google.login-service')
    email_domain = get_config('auth.google.hosted-domain')
elif auth_type == 'github':
    c.JupyterHub.authenticator_class = 'oauthenticator.GitHubOAuthenticator'
    c.GitHubOAuthenticator.oauth_callback_url = get_config('auth.github.callback-url')
    c.GitHubOAuthenticator.client_id = get_config('auth.github.client-id')
    c.GitHubOAuthenticator.client_secret = get_config('auth.github.client-secret')
    org_whitelist = get_config('auth.github.org_whitelist', [])
    if len(org_whitelist) != 0:
        c.GitHubOAuthenticator.github_organization_whitelist = org_whitelist
elif auth_type == 'cilogon':
    c.JupyterHub.authenticator_class = 'oauthenticator.CILogonOAuthenticator'
    c.CILogonOAuthenticator.oauth_callback_url = get_config('auth.cilogon.callback-url')
    c.CILogonOAuthenticator.client_id = get_config('auth.cilogon.client-id')
    c.CILogonOAuthenticator.client_secret = get_config('auth.cilogon.client-secret')
elif auth_type == 'gitlab':
    c.JupyterHub.authenticator_class = 'oauthenticator.gitlab.GitLabOAuthenticator'
    c.GitLabOAuthenticator.oauth_callback_url = get_config('auth.gitlab.callback-url')
    c.GitLabOAuthenticator.client_id = get_config('auth.gitlab.client-id')
    c.GitLabOAuthenticator.client_secret = get_config('auth.gitlab.client-secret')
elif auth_type == 'mediawiki':
    c.JupyterHub.authenticator_class = 'oauthenticator.mediawiki.MWOAuthenticator'
    c.MWOAuthenticator.client_id = get_config('auth.mediawiki.client-id')
    c.MWOAuthenticator.client_secret = get_config('auth.mediawiki.client-secret')
    c.MWOAuthenticator.index_url = get_config('auth.mediawiki.index-url')
elif auth_type == 'globus':
    c.JupyterHub.authenticator_class = 'oauthenticator.globus.GlobusOAuthenticator'
    c.GlobusOAuthenticator.oauth_callback_url = get_config('auth.globus.callback-url')
    c.GlobusOAuthenticator.client_id = get_config('auth.globus.client-id')
    c.GlobusOAuthenticator.client_secret = get_config('auth.globus.client-secret')
    c.GlobusOAuthenticator.identity_provider = get_config('auth.globus.identity-provider', '')
elif auth_type == 'hmac':
    c.JupyterHub.authenticator_class = 'hmacauthenticator.HMACAuthenticator'
    c.HMACAuthenticator.secret_key = bytes.fromhex(get_config('auth.hmac.secret-key'))
elif auth_type == 'dummy':
    c.JupyterHub.authenticator_class = 'dummyauthenticator.DummyAuthenticator'
    c.DummyAuthenticator.password = get_config('auth.dummy.password', None)
elif auth_type == 'tmp':
    c.JupyterHub.authenticator_class = 'tmpauthenticator.TmpAuthenticator'
elif auth_type == 'lti':
    c.JupyterHub.authenticator_class = 'ltiauthenticator.LTIAuthenticator'
    c.LTIAuthenticator.consumers = get_config('auth.lti.consumers')
elif auth_type == 'ldap':
    c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
    c.LDAPAuthenticator.server_address = get_config('auth.ldap.server.address')
    set_config_if_not_none(c.LDAPAuthenticator, 'server_port', 'auth.ldap.server.port')
    set_config_if_not_none(c.LDAPAuthenticator, 'use_ssl', 'auth.ldap.server.ssl')
    set_config_if_not_none(c.LDAPAuthenticator, 'allowed_groups', 'auth.ldap.allowed-groups')
    c.LDAPAuthenticator.bind_dn_template = get_config('auth.ldap.dn.templates')
    set_config_if_not_none(c.LDAPAuthenticator, 'lookup_dn', 'auth.ldap.dn.lookup')
    set_config_if_not_none(c.LDAPAuthenticator, 'lookup_dn_search_filter', 'auth.ldap.dn.search.filter')
    set_config_if_not_none(c.LDAPAuthenticator, 'lookup_dn_search_user', 'auth.ldap.dn.search.user')
    set_config_if_not_none(c.LDAPAuthenticator, 'lookup_dn_search_password', 'auth.ldap.dn.search.password')
    set_config_if_not_none(c.LDAPAuthenticator, 'lookup_dn_user_dn_attribute', 'auth.ldap.dn.user.dn-attribute')
    set_config_if_not_none(c.LDAPAuthenticator, 'escape_userdn', 'auth.ldap.dn.user.escape')
    set_config_if_not_none(c.LDAPAuthenticator, 'valid_username_regex', 'auth.ldap.dn.user.valid-regex')
    set_config_if_not_none(c.LDAPAuthenticator, 'user_search_base', 'auth.ldap.dn.user.search-base')
    set_config_if_not_none(c.LDAPAuthenticator, 'user_attribute', 'auth.ldap.dn.user.attribute')
elif auth_type == 'custom':
    # full_class_name looks like "myauthenticator.MyAuthenticator".
    # To create a docker image with this class availabe, you can just have the
    # following Dockerifle:
    #   FROM jupyterhub/k8s-hub:v0.4
    #   RUN pip3 install myauthenticator
    full_class_name = get_config('auth.custom.class-name')
    c.JupyterHub.authenticator_class = full_class_name
    auth_class_name = full_class_name.rsplit('.', 1)[-1]
    auth_config = c[auth_class_name]
    auth_config.update(get_config('auth.custom.config') or {})
else:
    raise ValueError("Unhandled auth type: %r" % auth_type)

auth_scopes = get_config('auth.scopes')
if auth_scopes:
    c.OAuthenticator.scope = auth_scopes

c.Authenticator.enable_auth_state = get_config('auth.state.enabled', False)

def generate_user_email(spawner):
    """
    Used as the EMAIL environment variable
    """
    return '{username}@{domain}'.format(
        username=spawner.user.name, domain=email_domain
    )

def generate_user_name(spawner):
    """
    Used as GIT_AUTHOR_NAME and GIT_COMMITTER_NAME environment variables
    """
    return spawner.user.name

c.KubeSpawner.environment = {
    'EMAIL': generate_user_email,
    # git requires these committer attributes
    'GIT_AUTHOR_NAME': generate_user_name,
    'GIT_COMMITTER_NAME': generate_user_name
}

c.KubeSpawner.environment.update(get_config('singleuser.extra-env', {}))

# Enable admins to access user servers
c.JupyterHub.admin_access = get_config('auth.admin.access')
c.Authenticator.admin_users = get_config('auth.admin.users', [])
c.Authenticator.whitelist = get_config('auth.whitelist.users', [])

c.JupyterHub.base_url = get_config('hub.base_url')

c.JupyterHub.services = []

if get_config('cull.enabled', False):
    cull_timeout = get_config('cull.timeout')
    cull_every = get_config('cull.every')
    cull_concurrency = get_config('cull.concurrency')
    cull_cmd = [
        '/usr/local/bin/cull_idle_servers.py',
        '--timeout=%s' % cull_timeout,
        '--cull-every=%s' % cull_every,
        '--concurrency=%s' % cull_concurrency,
        '--url=http://127.0.0.1:8081' + url_path_join(c.JupyterHub.base_url, 'hub/api'),
    ]

    if get_config('cull.users'):
        cull_cmd.append('--cull-users')

    # FIXME: remove version check when we require jupyterhub 0.9 in the chart
    # that will also mean we can remove the podCuller image
    import jupyterhub
    from distutils.version import LooseVersion as V
    cull_max_age = get_config('cull.max-age')
    if cull_max_age and V(jupyterhub.__version__) >= V('0.9'):
        cull_cmd.append('--max-age=%s' % cull_max_age)

    c.JupyterHub.services.append({
        'name': 'cull-idle',
        'admin': True,
        'command': cull_cmd,
    })

for name, service in get_config('hub.services', {}).items():
    api_token = get_secret('services.token.%s' % name)
    # jupyterhub.services is a list of dicts, but
    # in the helm chart it is a dict of dicts for easier merged-config
    service.setdefault('name', name)
    if api_token:
        service['api_token'] = api_token
    c.JupyterHub.services.append(service)


c.JupyterHub.db_url = get_config('hub.db_url')
c.JupyterHub.allow_named_servers = get_config('hub.allow-named-servers', False)

cmd = get_config('singleuser.cmd', None)
if cmd:
    c.Spawner.cmd = cmd

default_url = get_config('singleuser.default-url', None)
if default_url:
    c.Spawner.default_url = default_url

cloud_metadata = get_config('singleuser.cloud-metadata', {})

if not cloud_metadata.get('enabled', False):
    # Use iptables to block access to cloud metadata by default
    network_tools_image_name = get_config('singleuser.network-tools.image.name')
    network_tools_image_tag = get_config('singleuser.network-tools.image.tag')
    ip_block_container = client.V1Container(
        name="block-cloud-metadata",
        image=f"{network_tools_image_name}:{network_tools_image_tag}",
        command=[
            'iptables',
            '-A', 'OUTPUT',
            '-d', cloud_metadata.get('ip', '169.254.169.254'),
            '-j', 'DROP'
        ],
        security_context=client.V1SecurityContext(
            privileged=True,
            run_as_user=0,
            capabilities=client.V1Capabilities(add=['NET_ADMIN'])
        )
    )

    c.KubeSpawner.init_containers.append(ip_block_container)

scheduler_strategy = get_config('singleuser.scheduler-strategy', 'spread')

if scheduler_strategy == 'pack':
    # FIXME: Support setting affinity directly in KubeSpawner
    c.KubeSpawner.extra_pod_config = {
        'affinity': {
            'podAffinity': {
                'preferredDuringSchedulingIgnoredDuringExecution': [{
                    'weight': 50,
                    'podAffinityTerm': {
                        'labelSelector': {
                            'matchExpressions': [{
                                'key': 'component',
                                'operator': 'In',
                                'values': ['hub']
                            }]
                        },
                        'topologyKey': 'kubernetes.io/hostname'
                    }
                }, {
                    'weight': 5,
                    'podAffinityTerm': {
                        'labelSelector': {
                            'matchExpressions': [{
                                'key': 'component',
                                'operator': 'In',
                                'values': ['singleuser-server']
                            }]
                        },
                        'topologyKey': 'kubernetes.io/hostname'
                    }
                }],
            }
        }
    }

if get_config('debug.enabled', False):
    c.JupyterHub.log_level = 'DEBUG'
    c.Spawner.debug = True

extra_configs = sorted(glob.glob('/etc/jupyterhub/config/hub.extra-config.*.py'))
for ec in extra_configs:
    load_subconfig(ec)

#
# Custom code (previously in config-rdp.yaml)
#

c.JupyterHub.cookie_max_age_days = 0.02083333333
c.JupyterHub.template_paths = ['/usr/local/share/jupyterhub/new_templates']
c.KubeSpawner.profile_form_template = """
    <input type='hidden' id='jupyterhub-screen-resolution-width' name='jupyterhub-screen-resolution-width'/>
    <input type='hidden' id='jupyterhub-screen-resolution-heigth' name='jupyterhub-screen-resolution-heigth'/>
    <script>
    document.getElementById('jupyterhub-screen-resolution-heigth').value=window.innerHeight
    document.getElementById('jupyterhub-screen-resolution-width').value=window.innerWidth
    // JupyterHub 0.8 applied form-control indisciminately to all form elements.
    // Can be removed once we stop supporting JupyterHub 0.8
    $(document).ready(function() {
        $('#kubespawner-profiles-list input[type="radio"]').removeClass('form-control');
    });
    </script>
    <style>
    /* The profile description should not be bold, even though it is inside the <label> tag */
    #kubespawner-profiles-list label p {
        font-weight: normal;
    }
    </style>
    <div class='form-group' id='kubespawner-profiles-list'>
    {% for profile in profile_list %}
    <label for='profile-item-{{ loop.index0 }}' class='form-control input-group'>
        <div class='col-md-1'>
            <input type='radio' name='profile' id='profile-item-{{ loop.index0 }}' value='{{ loop.index0 }}' {% if profile.default %}checked{% endif %} />
        </div>
        <div class='col-md-11'>
            <strong>{{ profile.display_name }}</strong>
            {% if profile.description %}
            <p>{{ profile.description }}</p>
            {% endif %}
        </div>
    </label>
    {% endfor %}
    </div>
    """

from adrf import KubeSpawner as ADRFKubeSpawner
c.JupyterHub.spawner_class = ADRFKubeSpawner

import os
import ldap3
import string
import escapism
def profile_list_function(spawner):
    result_arr = []
    username = spawner.user.name
    ldapServer = ldap3.Server(os.environ["LDAP_URL"])
    ldap_conn = ldap3.Connection(server=ldapServer, user=os.environ["LDAP_USER"], password=os.environ["LDAP_PASSWORD"])
    ldap_conn.bind()
    ldap_conn.search(os.environ["LDAP_PROJECTS_BASE"], '(member=uid=%s,ou=People,dc=adrf,dc=info)' % (username), attributes=['cn', 'gidNumber'], search_scope=ldap3.SUBTREE)
    ldap_projects = ldap_conn.entries
    safe_chars = set(string.ascii_lowercase + string.digits)
    for proj in ldap_projects:
        proj_name = proj["cn"][0]
        proj_gid_number = proj["gidNumber"][0]
        if proj_name.startswith("project-"):
            proj_name_no_prefix = proj_name[8:]
        else:
            proj_name_no_prefix = proj_name
        friendly_name = proj_name_no_prefix.replace("_", " ").title()
        desktop = {'name': proj_name, 'display_name': friendly_name, 'kubespawner_override': {'image_spec': '441870321480.dkr.ecr.us-east-1.amazonaws.com/adrf-desktop:0.24', "env": {"RESOLUTION": "1024x768"}, "defaultUrl": "/index.html", "extra_pod_config": {"hostAliases": [{"ip": "127.0.0.1", "hostnames": ["jupyter.adrf.info", "pgadmin.adrf.info"]}]}, "extra_container_config": {"envFrom": [{"configMapRef": {"name": "jupyterhub-pod-config"} }] }}}
        desktop_jupyter = {"name": "jupyter", "image": '441870321480.dkr.ecr.us-east-1.amazonaws.com/adrf-base-jupyter:0.9-r', "args": ['start-notebook.sh', "--NotebookApp.token=''", "--port=9999" ], "env": [{"name":"JUPYTERHUB_USER", "value": username}, {"name": "JUPYTER_ENABLE_LAB", "value": "True"}], "ports": [{"containerPort": 9999, "name": "jupyter-port", "protocol": "TCP"}], "resources": {"requests":{"memory": "1024Mi", "cpu": "500m"}, "limits": {"cpu": "500m"}}, "envFrom": [{"configMapRef": {"name": "jupyterhub-pod-config"} }]}
        desktop_oauth = {"name": "jupyterhub-oauth", "image": '441870321480.dkr.ecr.us-east-1.amazonaws.com/adrf-jupyterhub-nginx-oauth:0.7', "env": [ {'name': k, 'value': v} for k, v in (spawner.get_env() or {}).items()], "ports": [{"containerPort": 9095, "name": "jhub-oauth", "protocol": "TCP"}], "resources": {"requests":{"memory": "32Mi", "cpu": "10m"}, "limits": {"memory": "64Mi", "cpu": "20m"}}}
        volumes = [{"name": "config", "configMap": {"name": "jupyterhub-pod-config"}}, {"name": "condaenv", "nfs": {"path":  "/mnt/nfs_storage/conda_envs", "server": "10.10.2.10"}}, {"name": "jupyterkernels", "nfs": {"path":  "/mnt/nfs_storage/jupyter_kernels_r", "server": "10.10.2.10"}}, {"name": "dshm", "emptyDir": {"medium": "Memory"}}]
        volume_mounts = [{"name": "config", "mountPath": "/etc/jupyterhub/config/"}, {"mountPath": "/opt/conda/envs", "name": "condaenv", "subPath": ""}, {"mountPath": "/usr/local/share/jupyter/kernels", "name": "jupyterkernels", "subPath": ""}, {"mountPath": "/dev/shm", "name": "dshm"}]
    
        
        project_shared_name = escapism.escape("project-shared-%s" % proj_name_no_prefix, safe=safe_chars, escape_char='-').lower()
        project_user_name = escapism.escape("project-user-%s" % proj_name_no_prefix, safe=safe_chars, escape_char='-').lower()
        volumes.append({"name": project_shared_name, "nfs": {"path": "/mnt/nfs_storage/project_directories/%s/shared" % proj_name_no_prefix, "server": "stuffed.adrf.info"}})
        volumes.append({"name": project_user_name, "nfs": {"path":  "/mnt/nfs_storage/project_directories/%s/user/%s" % (proj_name_no_prefix, username), "server": "stuffed.adrf.info"}})
        volume_mounts.append({"mountPath": "/projects/%s/shared" % proj_name_no_prefix, "name": project_shared_name, "subPath": ""})
        volume_mounts.append({"mountPath": "/nfshome/%s" % username, "name": project_user_name, "subPath": ""})
        desktop['kubespawner_override']['volumes'] = volumes
        desktop['kubespawner_override']['volume_mounts'] = volume_mounts
        desktop_jupyter['volume_mounts'] = volume_mounts
        desktop["kubespawner_override"]["extra_containers"]=[desktop_jupyter, desktop_oauth]
        result_arr.append(desktop)
    return result_arr
c.KubeSpawner.profile_list = profile_list_function
c.KubeSpawner.start_timeout = 900
c.KubeSpawner.http_timeout = 900

