from kubespawner.spawner import KubeSpawner as KSO
from tornado import gen
from tornado.ioloop import IOLoop

class KubeSpawner(KSO):
  def get_pod_manifest(self):
    if self.extra_containers:
      for container in self.extra_containers:
        if "name" in container and container["name"] == "jupyterhub-oauth":
          container["env"] = [ {'name': k, 'value': v} for k, v in (self.get_env() or {}).items()]
    return super(KubeSpawner, self).get_pod_manifest()

  async def add_project_to_auth_state(self, proj_id):
    auth_state = await self.user.get_auth_state()
    if auth_state:
      self.log.error("auth_state = ")
      self.log.error(auth_state)
      auth_state['selected_project'] = proj_id
      await self.user.save_auth_state(auth_state)

  def options_from_form(self, formdata):
    self.log.error("formdata = ")
    self.log.error(formdata)
    if not self.profile_list or not hasattr(self, '_profile_list'):
      return formdata
    # Default to first profile if somehow none is provided
    selected_profile = int(formdata.get('profile', [0])[0])
    resolution_width = int(formdata.get('jupyterhub-screen-resolution-width', [1024])[0])
    if resolution_width > 1920:
      resolution_width = 1920
    resolution_heigth = int(formdata.get('jupyterhub-screen-resolution-heigth', [768])[0])
    if resolution_heigth > 1080:
      resolution_heigth = 1080
    options = self._profile_list[selected_profile]
    self.log.debug("Applying KubeSpawner override for profile '%s'", options['display_name'])
    kubespawner_override = options.get('kubespawner_override', {})
    IOLoop.current().spawn_callback(self.add_project_to_auth_state, options['name'])
    if "env" not in kubespawner_override:
      kubespawner_override["env"] = {}
    kubespawner_override["env"]["RESOLUTION"] = "%dx%d" % (resolution_width, resolution_heigth)
    for k, v in kubespawner_override.items():
      if callable(v):
        v = v(self)
        self.log.debug(".. overriding KubeSpawner value %s=%s (callable result)", k, v)
      else:
        self.log.debug(".. overriding KubeSpawner value %s=%s", k, v)
      setattr(self, k, v)
    return options
 
  def start(self):
    return super().start()

  @gen.coroutine
  def stop(self, now=False):
    return super().stop(now=now)


if __name__ == "__main__":
	pass
