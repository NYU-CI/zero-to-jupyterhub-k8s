import os
import ldap3
import string
import escapism

PROFILE_FORM_TEMPLATE = """
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
    desktop = {
      'name': proj_name, 
      'display_name': friendly_name, 
      'kubespawner_override': {
        'image_spec': os.environ.get('ADRF_POD_DESKTOP_IMAGE'), 
        "env": {
          "RESOLUTION": "1024x768"
        }, 
        "defaultUrl": "/index.html", 
        "extra_pod_config": {
          "hostAliases": [
            {"ip": "127.0.0.1", "hostnames": ["jupyter.adrf.info", "pgadmin.adrf.info"]}
          ]
        }, 
        "extra_container_config": {
          "envFrom": [
            {
              "configMapRef": {
                "name": "jupyterhub-pod-config"
              } 
            }
          ]
        }
      }
    }
    desktop_jupyter = {
      "name": "jupyter", 
      "image": os.environ.get('ADRF_POD_JUPYTER_IMAGE'), 
      "args": ['start-notebook.sh', "--NotebookApp.token=''", "--port=9999" ], 
      "env": [
        {"name":"JUPYTERHUB_USER", "value": username}, 
        {"name":"JUPYTER_ENABLE_LAB", "value": "True"}
      ], 
      "ports": [
        {"containerPort": 9999, "name": "jupyter-port", "protocol": "TCP"}
      ],
      "resources": {
        "requests":{"memory": "1024Mi", "cpu": "500m"}, 
        "limits": {"cpu": "500m"}
      }, 
      "envFrom": [
        {"configMapRef": {"name": "jupyterhub-pod-config"} }
      ]
    }
    desktop_oauth = {
      "name": "jupyterhub-oauth",
      "image": os.environ.get('ADRF_POD_OAUTH_IMAGE'), 
      "env": [ {'name': k, 'value': v} for k, v in (spawner.get_env() or {}).items()], 
      "ports": [
        {"containerPort": 9095, "name": "jhub-oauth", "protocol": "TCP"}
      ], 
      "resources": {
        "requests":{"memory": "32Mi", "cpu": "10m"}, 
        "limits": {"memory": "64Mi", "cpu": "20m"}
      }
    }
    volumes = [
      {"name": "config", "configMap": {"name": "jupyterhub-pod-config"}}, 
      {"name": "condaenv", "nfs": {"path":  "/mnt/nfs_storage/conda_envs", "server": "10.10.2.10"}},
      {"name": "jupyterkernels", "nfs": {"path":  "/mnt/nfs_storage/jupyter_kernels_r", "server": "10.10.2.10"}}, 
      {"name": "dshm", "emptyDir": {"medium": "Memory"}}
    ]
    volume_mounts = [
      {"name": "config", "mountPath": "/etc/jupyterhub/config/"}, 
      {"mountPath": "/opt/conda/envs", "name": "condaenv", "subPath": ""}, 
      {"mountPath": "/usr/local/share/jupyter/kernels", "name": "jupyterkernels", "subPath": ""}, 
      {"mountPath": "/dev/shm", "name": "dshm"}
    ]

    project_shared_name = escapism.escape("project-shared-%s" % proj_name_no_prefix, safe=safe_chars, escape_char='-').lower()
    project_user_name = escapism.escape("project-user-%s" % proj_name_no_prefix, safe=safe_chars, escape_char='-').lower()
    volumes.append({
      "name": project_shared_name, 
      "nfs": {
        "path": "/mnt/nfs_storage/project_directories/%s/shared" % proj_name_no_prefix, 
        "server": "stuffed.adrf.info"
      }
    })
    volumes.append({
      "name": project_user_name, 
      "nfs": {
        "path":  "/mnt/nfs_storage/project_directories/%s/user/%s" % (proj_name_no_prefix, username), 
        "server": "stuffed.adrf.info"
      }
    })
    volume_mounts.append({
      "mountPath": "/projects/%s/shared" % proj_name_no_prefix, 
      "name": project_shared_name, 
      "subPath": ""
    })
    volume_mounts.append({
      "mountPath": "/nfshome/%s" % username, 
      "name": project_user_name, 
      "subPath": ""
    })
    desktop['kubespawner_override']['volumes'] = volumes
    desktop['kubespawner_override']['volume_mounts'] = volume_mounts
    desktop_jupyter['volume_mounts'] = volume_mounts
    desktop["kubespawner_override"]["extra_containers"]=[desktop_jupyter, desktop_oauth]
    result_arr.append(desktop)
  return result_arr
